import subprocess
import json
import os
import logging
from typing import Dict, Any, Optional


def parse_file(path, output="cpg.bin", language="c"):
    abspath = os.path.abspath(path)
    work_dir = os.path.dirname(abspath)
    output_path = os.path.join(work_dir, output)
    cmd = ["joern-parse", abspath, "--language", language, "--output", output_path]

    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error parsing file {path}: {e}")
        raise


def scan_file(path):
    abspath = os.path.abspath(path)
    work_dir = os.path.dirname(abspath)
    cmd = ["joern-scan", abspath, "--overwrite", "--tags", "all"]

    try:
        result = subprocess.run(
            cmd, cwd=work_dir, capture_output=True, text=True, check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Error scanning file {path}: {e}")
        raise


class JoernRunner:
    def __init__(self, cpg_path: str, joern_bin: str = "joern"):
        """
        :param cpg_path: 路径到 cpg.bin 文件
        :param joern_bin: joern 可执行文件路径（默认 "joern"）
        """
        self.cpg_path = os.path.abspath(cpg_path)
        self.joern_bin = joern_bin
        if not os.path.exists(self.cpg_path):
            raise FileNotFoundError(f"CPG file not found: {self.cpg_path}")
        # 验证 joern 是否可用
        try:
            subprocess.run(
                [self.joern_bin, "--help"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError("Joern is not installed or not in PATH")

    def run_script(
        self, script_path: str, params: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        运行 Joern 脚本并返回 JSON 结果

        :param script_path: .sc 脚本路径
        :param params: 传递给脚本的参数，如 {"func": "foo", "sink": "strcpy"}
        :return: 解析后的 JSON 对象（dict）
        """
        if not os.path.exists(script_path):
            raise FileNotFoundError(f"Script not found: {script_path}")

        # 构建命令
        cmd = [self.joern_bin, self.cpg_path, "--script", os.path.abspath(script_path)]

        # 添加 -D 参数
        if params:
            for key, value in params.items():
                cmd.extend(["-D", f"{key}={value}"])

        # 设置环境变量：让脚本能找到环境变量
        env = os.environ.copy()

        # 这里我们临时切换工作目录到 cpg 所在目录
        work_dir = os.path.dirname(self.cpg_path)

        try:
            result = subprocess.run(
                cmd,
                cwd=work_dir,  # 在 cpg 所在目录运行
                capture_output=True,
                text=True,
                timeout=30,  # 防止死循环
                env=env,
            )

            if result.returncode != 0:
                logging.warning(f"Joern script failed: {result.stderr}")
                # 尝试解析 stdout 是否有部分 JSON
                try:
                    return {"result": json.loads(result.stdout)}
                except:
                    return {
                        "error": "joern_script_failed",
                        "stderr": result.stderr,
                        "stdout": result.stdout,
                        "returncode": result.returncode,
                    }

            # 尝试解析 stdout 为 JSON
            if result.stdout.strip():
                try:
                    json_data = result.stdout.split("Json:")[-1].strip()
                    return {"result": json.loads(json_data)}
                except json.JSONDecodeError as e:
                    return {
                        "error": "json_decode_failed",
                        "raw_output": result.stdout,
                        "exception": str(e),
                    }
            else:
                return {"error": "empty_output"}

        except subprocess.TimeoutExpired:
            return {"error": "timeout", "message": "Joern script timed out (>30s)"}
        except Exception as e:
            return {"error": "exception", "message": str(e)}
