import subprocess
import os
import logging
from typing import Dict, Any, Optional

class SemgrepRunner:
    def __init__(self, semgrep_bin: str = "semgrep"):
        """
        :param semgrep_bin: semgrep 可执行文件路径（默认 "semgrep"）
        """
        self.semgrep_bin = semgrep_bin
        # 验证 semgrep 是否可用
        try:
            subprocess.run([self.semgrep_bin, "--version"], 
                           stdout=subprocess.DEVNULL, 
                           stderr=subprocess.DEVNULL, 
                           check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError("Semgrep is not installed or not in PATH")

    def run_rule(self, rule_path: str, target_path: str, output_path: str ) -> Dict[str, Any]:

        if not os.path.exists(rule_path):
            raise FileNotFoundError(f"Rule file not found: {rule_path}")
        if not os.path.exists(target_path):
            raise FileNotFoundError(f"Target path not found: {target_path}")

        cmd = [
            self.semgrep_bin,
            'scan',
            os.path.abspath(target_path),
            "--config="+ os.path.abspath(rule_path),
            "--json",
            "--json-output="+ os.path.abspath(output_path)
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30  # 防止死循环
            )

            if result.returncode != 0 and result.returncode != 1:
                logging.warning(f"Semgrep failed: {result}")
                return {
                    "error": "semgrep_failed",
                    "stderr": result.stderr,
                    "stdout": result.stdout,
                    "returncode": result.returncode
                }


            return {'result': result}

        except subprocess.TimeoutExpired:
            return {"error": "timeout", "message": "Semgrep timed out (>30s)"}
        except Exception as e:
            return {"error": "exception", "message": str(e)}
