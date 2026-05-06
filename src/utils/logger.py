import logging
import sys


def setup_logger(
    level: str = "INFO",
    format_string: str | None = None,
    file_path: str | None = None,
) -> logging.Logger:
    """配置结构化日志

    Args:
        level: 日志级别
        format_string: 日志格式
        file_path: 可选的日志文件路径

    Returns:
        配置好的 logger 实例
    """
    if format_string is None:
        format_string = (
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
        )

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    formatter = logging.Formatter(format_string, datefmt="%Y-%m-%d %H:%M:%S")

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    root.addHandler(console)

    if file_path:
        fh = logging.FileHandler(file_path, encoding="utf-8")
        fh.setFormatter(formatter)
        root.addHandler(fh)

    return root
