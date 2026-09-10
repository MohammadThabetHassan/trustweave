"""Versioned symbol tables used to propose an action class from local Python source.

Every entry is a fully qualified dotted name or a resolved receiver origin. A bare
attribute name is never a member of any table here: matching ``.post`` or ``.execute``
without knowing what they were called on produces confident nonsense, so the analyzer
only ever matches a name it has resolved back to an import binding.

The tables are deliberately small and boring. A symbol earns a place only when its
presence in a call graph is strong evidence on its own; anything requiring judgement is
left out so the analyzer refuses instead of guessing.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Final

CATALOG_VERSION: Final[str] = "trustweave.dev/code-catalog/v1alpha1"

# --------------------------------------------------------------------------------------
# external: the process reaches something outside itself
# --------------------------------------------------------------------------------------

EXTERNAL_SYMBOLS: Final[frozenset[str]] = frozenset(
    {
        "requests.delete",
        "requests.get",
        "requests.head",
        "requests.options",
        "requests.patch",
        "requests.post",
        "requests.put",
        "requests.request",
        "httpx.delete",
        "httpx.get",
        "httpx.head",
        "httpx.options",
        "httpx.patch",
        "httpx.post",
        "httpx.put",
        "httpx.request",
        "httpx.stream",
        "urllib.request.build_opener",
        "urllib.request.urlopen",
        "urllib.request.urlretrieve",
        "websockets.connect",
        "smtplib.SMTP",
        "smtplib.SMTP_SSL",
        "ftplib.FTP",
        "socket.create_connection",
        "psycopg2.connect",
        "pymysql.connect",
    }
)

# Receiver origins: a value constructed from one of these carries the class on any call.
EXTERNAL_RECEIVERS: Final[frozenset[str]] = frozenset(
    {
        "requests.Session",
        "httpx.Client",
        "httpx.AsyncClient",
        "aiohttp.ClientSession",
        "http.client.HTTPConnection",
        "http.client.HTTPSConnection",
        "socket.socket",
        "smtplib.SMTP",
        "smtplib.SMTP_SSL",
        "ftplib.FTP",
        "paramiko.SSHClient",
        "boto3.client",
        "boto3.resource",
        "openai.OpenAI",
        "openai.AsyncOpenAI",
        "anthropic.Anthropic",
        "anthropic.AsyncAnthropic",
        "slack_sdk.WebClient",
    }
)

# Command names that make a subprocess call network egress rather than local execution.
EGRESS_COMMANDS: Final[frozenset[str]] = frozenset(
    {"curl", "wget", "scp", "ssh", "rsync", "nc", "ncat", "sftp"}
)

# --------------------------------------------------------------------------------------
# write: the process changes durable state
# --------------------------------------------------------------------------------------

WRITE_SYMBOLS: Final[frozenset[str]] = frozenset(
    {
        "os.chmod",
        "os.chown",
        "os.link",
        "os.makedirs",
        "os.mkdir",
        "os.remove",
        "os.removedirs",
        "os.rename",
        "os.replace",
        "os.rmdir",
        "os.symlink",
        "os.truncate",
        "os.unlink",
        "os.utime",
        "os.write",
        "shutil.copy",
        "shutil.copy2",
        "shutil.copyfile",
        "shutil.copytree",
        "shutil.make_archive",
        "shutil.move",
        "shutil.rmtree",
        "shutil.unpack_archive",
    }
)

WRITE_RECEIVER_METHODS: Final[frozenset[str]] = frozenset(
    {
        "chmod",
        "hardlink_to",
        "mkdir",
        "rename",
        "replace",
        "rmdir",
        "symlink_to",
        "touch",
        "unlink",
        "write_bytes",
        "write_text",
    }
)

PATH_RECEIVERS: Final[frozenset[str]] = frozenset({"pathlib.Path", "pathlib.PurePath"})

# Leading SQL keyword decides the class of an otherwise identical execute() call.
SQL_WRITE_TOKENS: Final[frozenset[str]] = frozenset(
    {
        "alter",
        "create",
        "delete",
        "drop",
        "grant",
        "insert",
        "merge",
        "replace",
        "truncate",
        "update",
        "upsert",
    }
)

SQL_READ_TOKENS: Final[frozenset[str]] = frozenset(
    {"describe", "explain", "pragma", "select", "show", "with"}
)

DB_EXECUTE_METHODS: Final[frozenset[str]] = frozenset({"execute", "executemany", "exec_driver_sql"})

# --------------------------------------------------------------------------------------
# sensitive: credentials, secrets, or the ability to run arbitrary code
# --------------------------------------------------------------------------------------

SENSITIVE_SYMBOLS: Final[frozenset[str]] = frozenset(
    {
        "os.execl",
        "os.execle",
        "os.execlp",
        "os.execv",
        "os.execve",
        "os.execvp",
        "os.popen",
        "os.posix_spawn",
        "os.spawnl",
        "os.spawnv",
        "os.system",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.getoutput",
        "subprocess.run",
        "pty.spawn",
        "pickle.load",
        "pickle.loads",
        "marshal.loads",
        "netrc.netrc",
        "keyring.get_password",
        "keyring.set_password",
        "paramiko.RSAKey.from_private_key_file",
    }
)

# Environment variable name tokens that indicate a secret rather than configuration.
SECRET_ENV_TOKENS: Final[frozenset[str]] = frozenset(
    {
        "apikey",
        "auth",
        "credential",
        "credentials",
        "key",
        "passphrase",
        "password",
        "private",
        "pwd",
        "secret",
        "session",
        "token",
    }
)

# Tokens that neutralise a SECRET_ENV_TOKENS hit: these name a location, not a secret.
BENIGN_ENV_TOKENS: Final[frozenset[str]] = frozenset(
    {"file", "id", "keyring", "name", "path", "url"}
)

# Credential-bearing paths. A constant string reaching a read API that matches one of
# these is treated as credential access.
CREDENTIAL_PATH_TOKENS: Final[frozenset[str]] = frozenset(
    {
        ".aws/credentials",
        ".docker/config.json",
        ".env",
        ".git-credentials",
        ".ssh/",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
        "kubeconfig",
    }
)

CREDENTIAL_PATH_SUFFIXES: Final[frozenset[str]] = frozenset({".p12", ".pem", ".pfx"})

# Lexical PII tokens. These never assign a class on their own; see code_analysis.
PII_TOKENS: Final[frozenset[str]] = frozenset(
    {
        "address",
        "birthdate",
        "creditcard",
        "cvv",
        "dob",
        "iban",
        "mrn",
        "passport",
        "salary",
        "ssn",
        "taxid",
    }
)

HIGH_SPECIFICITY_PII_TOKENS: Final[frozenset[str]] = frozenset(
    {"creditcard", "cvv", "iban", "mrn", "passport", "ssn"}
)

# --------------------------------------------------------------------------------------
# read: recognised, and positively harmless
# --------------------------------------------------------------------------------------

READ_SYMBOLS: Final[frozenset[str]] = frozenset(
    {
        "csv.DictReader",
        "csv.reader",
        "json.load",
        "json.loads",
        "os.listdir",
        "os.scandir",
        "os.stat",
        "os.walk",
    }
)

READ_RECEIVER_METHODS: Final[frozenset[str]] = frozenset(
    {
        "exists",
        "glob",
        "is_dir",
        "is_file",
        "iterdir",
        "read_bytes",
        "read_text",
        "rglob",
        "stat",
    }
)

# --------------------------------------------------------------------------------------
# Descriptive capability labels. These annotate a proposal; they never authorize one.
# --------------------------------------------------------------------------------------

# Framework types that wrap a tool's return value. Constructing one performs no effect, so
# counting it as a symbol the catalog cannot describe let it suppress a classification the
# analyzer had already made: a tool that deleted and copied a directory tree was reported
# unknown because it returned its result the way the protocol requires.
RESULT_CONSTRUCTORS: Final[frozenset[str]] = frozenset(
    {
        "mcp.types.TextContent",
        "mcp.types.ImageContent",
        "mcp.types.EmbeddedResource",
        "mcp.types.Tool",
        "mcp.types.Resource",
        "mcp.types.Prompt",
        "mcp.types.PromptMessage",
        "langchain_core.documents.Document",
        "langchain_core.messages.AIMessage",
        "langchain_core.messages.HumanMessage",
        "langchain_core.messages.ToolMessage",
        "llama_index.core.schema.TextNode",
        "llama_index.core.schema.Document",
    }
)

CAPABILITY_BY_ACTION_CLASS: Final[MappingProxyType[str, str]] = MappingProxyType(
    {
        "external": "network.egress",
        "write": "storage.write",
        "sensitive": "process.privileged",
        "read": "storage.read",
    }
)

ACTION_CLASS_PRECEDENCE: Final[tuple[str, ...]] = ("sensitive", "external", "write", "read")

UNKNOWN_ACTION_CLASS: Final[str] = "unknown"
UNKNOWN_TRUST: Final[str] = "unknown"
REVIEW_PLACEHOLDER: Final[str] = "REVIEW_REQUIRED"
