#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import random
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

import click
from loguru import logger

try:
    import requests
except Exception:  # 允许在无 requests 时仍能运行非 HTTP 探测
    requests = None  # type: ignore

# 目标端口与服务映射可以由 CLI 或配置覆盖
DEFAULT_SPECIFIED_PORTS = [
    {"proto": "tcp", "port": 80},
    {"proto": "udp", "port": 53},
]

DEFAULT_TARGET_SERVICES = [
    {"name": "ssh", "proto": "tcp", "port": 22},
    {"name": "ftp", "proto": "tcp", "port": 21},
    {"name": "mysql", "proto": "tcp", "port": 3306},
    {"name": "http", "proto": "tcp", "port": 80},
]

RANDOM_HIGH_PORT_RANGE = (20000, 65535)


def run(cmd: List[str], capture: bool = False, check: bool = True) -> subprocess.CompletedProcess:
    logger.debug("$ {}", " ".join(cmd))
    return subprocess.run(cmd, capture_output=capture, text=True, check=check)


def ensure_output_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


@dataclass
class ScanConfig:
    specified_ports: list
    target_services: list
    output_dir: Path
    rate: int = 10000
    iface: Optional[str] = None
    source_port: Optional[int] = None
    cooldown_threshold: float = 0.01
    seed: int = 1337
    exclude_file: Optional[Path] = None
    scanner: str = "auto"  # auto|zmap|masscan


def pick_random_high_port(seed: int) -> int:
    random.seed(seed)
    return random.randint(*RANDOM_HIGH_PORT_RANGE)


def which(name: str) -> Optional[str]:
    return shutil.which(name)


# ------------------------- 扫描器封装 -------------------------

def zmap_scan(target_port: int, rate: int, iface: Optional[str], source_port: Optional[int], output: Path, exclude_file: Optional[Path] = None) -> Path:
    ensure_output_dir(output.parent)
    cmd = [
        "zmap",
        "-p",
        str(target_port),
        "-o",
        str(output),
        "-r",
        str(rate),
        "--verbosity=2",
    ]
    if iface:
        cmd += ["-i", iface]
    if source_port:
        cmd += ["--source-port", str(source_port)]
    if exclude_file:
        cmd += ["-w", str(exclude_file)]
    run(cmd)
    return output


def masscan_scan(target_port: int, rate: int, iface: Optional[str], source_port: Optional[int], output: Path, exclude_file: Optional[Path] = None) -> Path:
    ensure_output_dir(output.parent)
    # masscan 输出支持 -oL（列表）或 -oJ（JSON）。这里使用 -oL，之后统一转 .csv 兼容 extract。
    out_list = output.with_suffix(".list")
    cmd = [
        "masscan",
        "0.0.0.0/0",
        "-p",
        str(target_port),
        "--rate",
        str(rate),
        "-oL",
        str(out_list),
        "--wait",
        "0",
    ]
    if iface:
        cmd += ["-e", iface]
    if source_port:
        cmd += ["--source-port", str(source_port)]
    if exclude_file:
        cmd += ["--excludefile", str(exclude_file)]
    run(cmd)
    # 解析 -oL 为简单 CSV（ip,port）
    with open(out_list, "r", encoding="utf-8", errors="ignore") as rf, open(output, "w", encoding="utf-8") as wf:
        for line in rf:
            if line.startswith("Host:"):
                # 形如：Host: 1.2.3.4 () 80
                parts = line.strip().split()
                ip = parts[1]
                wf.write(f"{ip},{target_port}\n")
    return output


def scan_dispatch(cfg: ScanConfig, target_port: int, src_port: Optional[int], tag: str) -> Path:
    out = cfg.output_dir / f"scan_{tag}_src{src_port or 'auto'}_to{target_port}.csv"
    if cfg.scanner == "zmap" or (cfg.scanner == "auto" and which("zmap")):
        return zmap_scan(target_port=target_port, rate=cfg.rate, iface=cfg.iface, source_port=src_port, output=out, exclude_file=cfg.exclude_file)
    if cfg.scanner == "masscan" or (cfg.scanner == "auto" and which("masscan")):
        return masscan_scan(target_port=target_port, rate=cfg.rate, iface=cfg.iface, source_port=src_port, output=out, exclude_file=cfg.exclude_file)
    raise RuntimeError("未找到可用扫描器：请安装 zmap 或 masscan 并加入 PATH，或用 --scanner 指定")


# ------------------------- 简单应用层探测 -------------------------

def tcp_banner(target_ip: str, port: int, timeout: float = 3.0, payload: Optional[bytes] = None) -> Optional[str]:
    try:
        with socket.create_connection((target_ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if payload:
                s.sendall(payload)
            try:
                data = s.recv(256)
            except socket.timeout:
                data = b""
            return data.decode("latin-1", errors="ignore")
    except Exception:
        return None


def probe_http(ip: str, port: int) -> Optional[dict]:
    if requests is None:
        # 回退到原始 socket GET
        payload = f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: misconf-fw\r\n\r\n".encode()
        banner = tcp_banner(ip, port, payload=payload)
        if banner is None:
            return None
        return {"type": "raw", "data": banner[:256]}
    try:
        url = f"http://{ip}:{port}/"
        r = requests.get(url, timeout=5)
        return {"code": r.status_code, "server": r.headers.get("Server"), "len": len(r.content)}
    except Exception:
        return None


def probe_service(ip: str, svc_name: str, port: int) -> Optional[dict]:
    if svc_name == "http":
        return probe_http(ip, port)
    if svc_name == "ssh":
        banner = tcp_banner(ip, port)
        return {"banner": banner} if banner else None
    if svc_name == "ftp":
        banner = tcp_banner(ip, port)
        return {"banner": banner} if banner else None
    if svc_name == "mysql":
        banner = tcp_banner(ip, port)
        return {"banner": banner} if banner else None
    return None


def extract_ips_from_csv(csv_file: Path) -> Path:
    # csv: "ip,port"
    ip_list = csv_file.parent / (csv_file.stem + ".ips")
    with open(csv_file, "r", encoding="utf-8", errors="ignore") as f, open(ip_list, "w", encoding="utf-8") as w:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ip = line.split(",")[0]
            w.write(ip + "\n")
    return ip_list


def filter_ips_by_not_in(other: Path, base: Path, out: Path) -> Path:
    with open(base, "r") as fb:
        base_set = set(ip.strip() for ip in fb if ip.strip())
    with open(other, "r") as fo:
        other_set = set(ip.strip() for ip in fo if ip.strip())
    remaining = base_set - other_set
    with open(out, "w") as fw:
        for ip in sorted(remaining):
            fw.write(ip + "\n")
    return out


@click.group()
def cli():
    """三阶段扫描管道 (ZMap/Masscan + 内置应用层探测)。"""


@cli.command()
@click.option("--output-dir", type=click.Path(path_type=Path), default=Path("outputs"))
@click.option("--rate", type=int, default=10000)
@click.option("--iface", type=str, default=None)
@click.option("--exclude-file", type=click.Path(path_type=Path), default=None, help="排除文件 (IANA 保留地址等)")
@click.option("--seed", type=int, default=1337)
@click.option("--scanner", type=click.Choice(["auto", "zmap", "masscan"]), default="auto")
def run_all(output_dir: Path, rate: int, iface: Optional[str], exclude_file: Optional[Path], seed: int, scanner: str):
    cfg = ScanConfig(
        specified_ports=DEFAULT_SPECIFIED_PORTS,
        target_services=DEFAULT_TARGET_SERVICES,
        output_dir=output_dir,
        rate=rate,
        iface=iface,
        seed=seed,
        exclude_file=exclude_file,
        scanner=scanner,
    )

    ensure_output_dir(cfg.output_dir)

    # 第一阶段
    logger.info("阶段1：从指定端口扫描目标端口，得到初始主机列表")
    stage1_all_ips: List[Path] = []
    high_port = pick_random_high_port(cfg.seed)
    for spec in cfg.specified_ports:
        for svc in cfg.target_services:
            if svc["proto"] != "tcp":
                continue
            csv1 = scan_dispatch(cfg, target_port=svc["port"], src_port=spec["port"], tag=f"p{spec['port']}_to_{svc['name']}{svc['port']}")
            ips1 = extract_ips_from_csv(csv1)
            csv2 = scan_dispatch(cfg, target_port=svc["port"], src_port=high_port, tag=f"high{high_port}_to_{svc['name']}{svc['port']}")
            ips2 = extract_ips_from_csv(csv2)
            remaining = filter_ips_by_not_in(other=ips2, base=ips1, out=cfg.output_dir / f"stage1_{svc['name']}_from_{spec['port']}_only.ips")
            stage1_all_ips.append(remaining)

    # 合并 stage1 候选
    union_stage1 = cfg.output_dir / "stage1_candidates.ips"
    unique = set()
    for f in stage1_all_ips:
        with open(f, "r") as rf:
            for ip in rf:
                ip = ip.strip()
                if ip:
                    unique.add(ip)
    with open(union_stage1, "w") as wf:
        for ip in sorted(unique):
            wf.write(ip + "\n")

    # 第二阶段：对候选主机的指定端口发应用层探测
    logger.info("阶段2：应用层探测候选主机")
    responses_paths: List[Path] = []
    for spec in cfg.specified_ports:
        for svc in cfg.target_services:
            if svc["proto"] != "tcp":
                continue
            ip_input = union_stage1
            out_json = cfg.output_dir / f"stage2_{svc['name']}_on_{spec['port']}.jsonl"
            count = 0
            with open(ip_input, "r") as rf, open(out_json, "w", encoding="utf-8") as wf:
                for line in rf:
                    ip = line.strip()
                    if not ip:
                        continue
                    res = probe_service(ip, svc["name"], spec["port"])  # 指定端口=探测端口
                    if res is not None:
                        wf.write(json.dumps({"ip": ip, "service": svc["name"], "port": spec["port"], "result": res}, ensure_ascii=False) + "\n")
                        count += 1
            logger.info("{}:{} 探测响应 {} 条", svc["name"], spec["port"], count)
            responses_paths.append(out_json)

    # 第三阶段：高端口验证
    logger.info("阶段3：高端口验证并去除误报")
    verified_paths: List[Path] = []
    high_port2 = pick_random_high_port(cfg.seed + 1)
    for svc in cfg.target_services:
        if svc["proto"] != "tcp":
            continue
        csv_verify = scan_dispatch(cfg, target_port=svc["port"], src_port=high_port2, tag=f"verify_high{high_port2}_to_{svc['name']}{svc['port']}")
        ips_verify = extract_ips_from_csv(csv_verify)
        verified_paths.append(ips_verify)

    logger.info("完成。输出路径位于: {}", cfg.output_dir.resolve())


if __name__ == "__main__":
    cli() 