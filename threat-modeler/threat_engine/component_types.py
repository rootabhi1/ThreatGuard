"""Canonical component-type vocabulary — a dependency-free leaf module.

Both the analyzer (free-text extraction, structured parsing) and model_health
(normalization / validation) need the set of valid component types. Keeping it
here, importing nothing, means neither has to import the other for it — which is
what previously formed an ``analyzer`` <-> ``model_health`` import cycle.
"""
from __future__ import annotations

# Keyword map for heuristic extraction from a free-text system description
# (the "text description" input mode).
_TYPE_KEYWORDS = {
    "user":            ["user", "customer", "end user", "client app user"],
    "external_entity": ["third party", "external", "partner", "saas"],
    "webapp":          ["web app", "website", "front-end", "frontend", "portal", "spa", "react app",
                        "next.js", "nextjs", "angular", "vue", "svelte", "nuxt"],
    "mobile_app":      ["mobile app", "android", "ios", "react native", "flutter"],
    "api":             ["api", "backend", "rest service", "graphql", "grpc", "microservice", "service",
                        "fastapi", "express", "flask", "django", "spring", "rails"],
    # Cloud compute / edge
    "serverless":      ["lambda", "cloud function", "cloud functions", "serverless", "faas",
                        "azure function", "cloud run", "fargate"],
    "container":       ["docker", "container", "containerized", "ecs task"],
    "kubernetes":      ["kubernetes", "k8s", "eks", "gke", "aks", "openshift"],
    "service_mesh":    ["service mesh", "istio", "linkerd", "consul connect", "envoy mesh"],
    "api_gateway":     ["api gateway", "apigee", "kong gateway", "tyk"],
    "load_balancer":   ["load balancer", "load-balancer", "alb", "elb", "nlb", "haproxy"],
    "cdn":             ["cdn", "cloudfront", "fastly", "akamai", "content delivery"],
    "waf":             ["waf", "web application firewall"],
    "dns":             ["route 53", "route53", "dns", "cloudflare dns", "name server", "dns resolver"],
    "bastion":         ["bastion", "jump host", "jump box", "jump server", "jumpbox"],
    # Identity & auth
    "auth_service":    ["auth service", "authentication service", "auth", "oauth", "ldap", "saml",
                        "firebase auth"],
    "identity_provider": ["identity provider", "idp", "sso", "okta", "auth0", "cognito", "keycloak",
                        "clerk", "entra", "azure ad", "ping identity", "workos", "jumpcloud", "onelogin"],
    "iam":             ["iam", "identity and access"],
    "secrets_manager": ["secrets manager", "secret manager", "hashicorp vault", "vault", "kms",
                        "key vault", "parameter store"],
    "admin_panel":     ["admin panel", "admin ui", "back-office", "back office"],
    # AI
    "llm":             ["llm", "large language model", "language model", "gpt", "openai", "chatgpt",
                        "bedrock", "sagemaker", "hugging face", "inference endpoint", "model endpoint",
                        "generative ai", "vertex ai"],
    "vector_db":       ["vector database", "vector db", "pinecone", "weaviate", "qdrant", "milvus",
                        "chroma", "embedding store"],
    # Agentic AI — autonomous agents, tools, orchestration, memory, and guardrails.
    "ai_agent":        ["ai agent", "autonomous agent", "llm agent", "agent", "react agent",
                        "langchain agent", "autogpt", "babyagi", "copilot agent", "assistant agent"],
    "agent_orchestrator": ["agent orchestrator", "orchestrator", "multi-agent", "multi agent",
                        "agent supervisor", "crew", "crewai", "langgraph", "autogen", "agent router",
                        "planner agent", "agent framework"],
    "llm_tool":        ["llm tool", "agent tool", "tool call", "function call", "function calling",
                        "tool use", "tool-use", "code interpreter", "plugin"],
    "mcp_server":      ["mcp server", "mcp", "model context protocol", "tool server"],
    "agent_memory":    ["agent memory", "conversation memory", "long-term memory", "short-term memory",
                        "scratchpad", "episodic memory", "memory store"],
    "retriever":       ["retriever", "rag", "retrieval augmented", "retrieval-augmented",
                        "retrieval pipeline", "context retrieval", "document retriever"],
    "guardrail":       ["guardrail", "guardrails", "llm firewall", "prompt firewall", "content filter",
                        "safety filter", "input sanitizer for llm", "output validator"],
    "knowledge_base":  ["knowledge base", "knowledgebase", "kb", "document store for rag",
                        "grounding data", "corpus"],
    # Data
    "database":        ["database", "db", "postgres", "mysql", "mongodb", "dynamodb", "rds", "cassandra",
                        "cockroach", "mariadb", "sqlite", "mssql", "sql server", "oracle", "spanner",
                        "aurora", "neo4j", "influxdb", "timescale", "scylla"],
    "object_storage":  ["s3", "object storage", "object store", "blob storage", "minio", "gcs",
                        "azure blob", "cloud storage", "storage bucket"],
    "data_warehouse":  ["data warehouse", "warehouse", "bigquery", "snowflake", "redshift",
                        "clickhouse", "databricks"],
    "search_service":  ["elasticsearch", "opensearch", "solr", "algolia", "meilisearch", "typesense",
                        "search engine", "search cluster"],
    "data_pipeline":   ["data pipeline", "etl", "airflow", "dagster", "spark", "flink", "dbt",
                        "stream processor", "kinesis firehose", "glue job", "streaming pipeline"],
    "datastore":       ["datastore", "data lake", "hdfs", "ceph"],
    "cache":           ["redis", "memcached", "cache", "hazelcast", "varnish"],
    "queue":           ["queue", "kafka", "rabbitmq", "sqs", "pubsub", "event bus", "nats",
                        "activemq", "kinesis", "service bus", "celery"],
    "filesystem":      ["filesystem", "file storage", "nfs"],
    # Ops
    "scheduler":       ["scheduler", "cron", "scheduled job", "cron job", "task scheduler", "batch job"],
    "monitoring":      ["prometheus", "grafana", "datadog", "monitoring", "observability", "cloudwatch"],
    "notification_service": ["notification service", "push notification", "fcm", "apns",
                        "notification", "notifications"],
    # Messaging / external
    "email_service":   ["sendgrid", "mailgun", "postmark", "amazon ses", "aws ses", "smtp",
                        "email service", "mailchimp", "email provider"],
    "sms_gateway":     ["twilio", "sms gateway", "vonage", "nexmo", "sns sms", "text message"],
    "iot_device":      ["iot device", "iot", "sensor", "embedded device", "smart device",
                        "edge device", "telemetry"],
    "payment_service": ["stripe", "payment", "paypal", "billing", "square", "adyen", "razorpay", "braintree"],
}

# Types with no natural free-text keyword (set explicitly in structured input,
# the DFD editor, or by AI-vision diagram extraction). Everything else has a
# keyword mapping above so free-text descriptions detect it too.
_EXTRA_TYPES = ["config", "service", "worker", "vpc"]

# Human-facing list of valid component types (deduped, keyword-mapped first).
VALID_COMPONENT_TYPES = list(dict.fromkeys(list(_TYPE_KEYWORDS.keys()) + _EXTRA_TYPES))
