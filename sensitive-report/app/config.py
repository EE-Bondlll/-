"""成员C 服务配置：全部走环境变量，本地与 docker 两套环境自动适配。"""
import os


def _database_url() -> str:
    """数据库连接串。

    docker-compose 注入 POSTGRES_* 时自动用 PostgreSQL；
    否则回退本地 SQLite（零依赖，方便学生本机直接跑起来演示）。
    """
    pg_user = os.getenv("POSTGRES_USER")
    pg_pass = os.getenv("POSTGRES_PASSWORD")
    pg_host = os.getenv("POSTGRES_HOST", "postgres")
    pg_db = os.getenv("POSTGRES_DB")
    if pg_user and pg_pass and pg_db:
        return f"postgresql+psycopg2://{pg_user}:{pg_pass}@{pg_host}:5432/{pg_db}"
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return f"sqlite:///{os.path.join(here, 'data', 'sensitive.db')}"


DATABASE_URL = _database_url()

# LLM（与成员A 共用同一套 OpenAI 兼容配置；不配置则语义研判走规则兜底）
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.deepseek.com/v1")
LLM_MODEL = os.getenv("LLM_MODEL", "deepseek-chat")

# 告警通道（未配置时接口仍返回成功，仅记录日志，不阻塞主流程）
FEISHU_WEBHOOK = os.getenv("FEISHU_WEBHOOK", "")          # 飞书机器人 webhook
FEISHU_SECRET = os.getenv("FEISHU_SECRET", "")            # 可选签名校验
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "465"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
ALERT_MAIL_TO = os.getenv("ALERT_MAIL_TO", "")            # 收件人，逗号分隔
GENERAL_WEBHOOK = os.getenv("GENERAL_WEBHOOK", "")        # 通用 webhook

# 敏感检测限速
DEFAULT_QPS = int(os.getenv("SCAN_QPS", "5"))
REQUEST_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "20"))

# 告警去重：同一 signature 在该秒数内不重复告警
ALERT_DEDUP_SECONDS = int(os.getenv("ALERT_DEDUP_SECONDS", "86400"))

SERVICE_NAME = "sensitive-report"
SERVICE_VERSION = "0.4.0"
