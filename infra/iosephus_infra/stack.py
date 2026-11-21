"""Uma EC2 barata com Docker rodando MySQL, MongoDB e a API.

Segurança por padrão:
- nenhuma porta aberta para a internet; acesso por SSM Session Manager (sem SSH, sem chave);
- se quiser abrir o dashboard, passe -c acesso_cidr=SEU.IP/32 (só HTTP 80, só do seu IP);
- disco criptografado, IMDSv2 obrigatório, segredos gerados na própria instância (.env 600).

Custo: VPC sem NAT Gateway (que sozinho custaria ~US$ 32/mês) e uma t4g.small.
"""
from pathlib import Path

from aws_cdk import CfnOutput, Stack, Tags
from aws_cdk import aws_budgets as budgets
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_s3_assets as s3_assets
from aws_cdk import aws_ssm as ssm
from constructs import Construct

RAIZ_DO_REPO = Path(__file__).resolve().parents[2]
PARAMETRO_CODIGO = "/iosephus/codigo-s3"
COMPOSE_VERSAO = "v2.32.4"
BUILDX_VERSAO = "v0.20.1"
# SHA-256 dos checksums.txt de cada release. Ao trocar a versão, troque os hashes também
COMPOSE_SHA256 = {"aarch64": "0c4591cf3b1ed039adcd803dbbeddf757375fc08c11245b0154135f838495a2f",
                  "x86_64": "ed1917fb54db184192ea9d0717bcd59e3662ea79db48bff36d3475516c480a6b"}
BUILDX_SHA256 = {"aarch64": "f7d867e9f1a3c00b32dd580f56594e229df05e3fb1b083b7099c91c2e7d2ce1e",
                 "x86_64": "8c38f60308a895fa570f1410e453c5de11aafd65a99fa99965d96d24b6225a78"}


class IosephusStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        ctx = self.node.try_get_context
        email = ctx("email_alerta") or ""
        acesso_cidr = ctx("acesso_cidr") or ""
        orcamento = ctx("orcamento") or "iosephus-20usd"
        tipo = ctx("tipo_instancia") or "t4g.small"

        # Rede: 1 zona, só sub-rede pública, sem NAT Gateway
        vpc = ec2.Vpc(self, "Rede", max_azs=1, nat_gateways=0,
                      subnet_configuration=[ec2.SubnetConfiguration(
                          name="publica", subnet_type=ec2.SubnetType.PUBLIC, cidr_mask=24)])

        sg = ec2.SecurityGroup(self, "Firewall", vpc=vpc, allow_all_outbound=True,
                               description="Iosephus: fechado por padrao; HTTP so do CIDR informado")
        if acesso_cidr:
            sg.add_ingress_rule(ec2.Peer.ipv4(acesso_cidr), ec2.Port.tcp(80), "Dashboard e API")

        # Código do repositório vai para o S3 como asset (funciona com repo privado)
        codigo = s3_assets.Asset(self, "Codigo", path=str(RAIZ_DO_REPO), exclude=[
            "infra", ".git", ".github", ".env", "**/__pycache__", "**/.pytest_cache",
            "**/.venv", "**/venv", "api/tests", "**/node_modules"])
        parametro = ssm.StringParameter(self, "CodigoS3", parameter_name=PARAMETRO_CODIGO,
                                        string_value=codigo.s3_object_url,
                                        description="Pacote do código que a EC2 instala")

        papel = iam.Role(self, "PapelInstancia",
                         assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
                         managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name(
                             "AmazonSSMManagedInstanceCore")])
        codigo.grant_read(papel)
        parametro.grant_read(papel)

        dados_usuario = ec2.UserData.for_linux()
        dados_usuario.add_commands(_script_inicial(self.region))

        instancia = ec2.Instance(
            self, "Servidor",
            vpc=vpc, vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            associate_public_ip_address=True,
            instance_type=ec2.InstanceType(tipo),
            machine_image=ec2.MachineImage.latest_amazon_linux2023(cpu_type=ec2.AmazonLinuxCpuType.ARM_64),
            security_group=sg, role=papel, user_data=dados_usuario,
            user_data_causes_replacement=False,  # atualizar o código NÃO recria a máquina (nem apaga os bancos)
            require_imdsv2=True,
            block_devices=[ec2.BlockDevice(device_name="/dev/xvda", volume=ec2.BlockDeviceVolume.ebs(
                20, volume_type=ec2.EbsDeviceVolumeType.GP3, encrypted=True, delete_on_termination=True))],
        )
        Tags.of(instancia).add("Name", "iosephus")
        instancia.node.add_dependency(parametro)

        # Corte de gastos: ao atingir 90% do orçamento, a AWS desliga a EC2 sozinha
        if email:
            papel_orcamento = iam.Role(
                self, "PapelOrcamento",
                assumed_by=iam.ServicePrincipal("budgets.amazonaws.com"),
                managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSBudgetsActions_RolePolicyForResourceAdministrationWithSSM")])
            budgets.CfnBudgetsAction(
                self, "DesligarAoEstourar",
                budget_name=orcamento,
                action_type="RUN_SSM_DOCUMENTS",
                approval_model="AUTOMATIC",
                notification_type="ACTUAL",
                action_threshold=budgets.CfnBudgetsAction.ActionThresholdProperty(type="PERCENTAGE", value=90),
                execution_role_arn=papel_orcamento.role_arn,
                definition=budgets.CfnBudgetsAction.DefinitionProperty(
                    ssm_action_definition=budgets.CfnBudgetsAction.SsmActionDefinitionProperty(
                        subtype="STOP_EC2_INSTANCES", region=self.region,
                        instance_ids=[instancia.instance_id])),
                subscribers=[budgets.CfnBudgetsAction.SubscriberProperty(type="EMAIL", address=email)],
            )

        regiao = self.region
        iid = instancia.instance_id
        CfnOutput(self, "InstanciaId", value=iid)
        CfnOutput(self, "Atualizar", description="Instala a versão do código do último cdk deploy",
                  value=(f"aws ssm send-command --region {regiao} --instance-ids {iid} "
                         "--document-name AWS-RunShellScript "
                         "--parameters commands=/opt/iosephus/atualizar.sh"))
        CfnOutput(self, "TunelDashboard", description="Abre http://localhost:8000 sem expor porta",
                  value=(f"aws ssm start-session --region {regiao} --target {iid} "
                         "--document-name AWS-StartPortForwardingSession "
                         "--parameters portNumber=80,localPortNumber=8000"))
        CfnOutput(self, "Terminal", value=f"aws ssm start-session --region {regiao} --target {iid}")
        CfnOutput(self, "Desligar", value=f"aws ec2 stop-instances --region {regiao} --instance-ids {iid}")
        CfnOutput(self, "Ligar", value=f"aws ec2 start-instances --region {regiao} --instance-ids {iid}")
        CfnOutput(self, "IpPublico", value=(
            f"aws ec2 describe-instances --region {regiao} --instance-ids {iid} "
            "--query Reservations[0].Instances[0].PublicIpAddress --output text"))


def _script_inicial(regiao: str) -> str:
    """Roda uma vez, no primeiro boot. Não muda entre deploys (por isso a máquina não é recriada)."""
    return f"""set -euxo pipefail
dnf install -y docker unzip
systemctl enable --now docker

# Docker Compose e Buildx (o Amazon Linux 2023 não traz os plugins)
ARQ=$(uname -m | sed 's/aarch64/arm64/; s/x86_64/amd64/')
case "$(uname -m)" in
  aarch64) COMPOSE_SHA={COMPOSE_SHA256["aarch64"]}; BUILDX_SHA={BUILDX_SHA256["aarch64"]} ;;
  x86_64)  COMPOSE_SHA={COMPOSE_SHA256["x86_64"]}; BUILDX_SHA={BUILDX_SHA256["x86_64"]} ;;
  *) echo "arquitetura sem hash conhecido: $(uname -m)" >&2; exit 1 ;;
esac
PLUGINS=/usr/local/lib/docker/cli-plugins
mkdir -p "$PLUGINS"
curl -fsSL "https://github.com/docker/compose/releases/download/{COMPOSE_VERSAO}/docker-compose-linux-$(uname -m)" \\
  -o "$PLUGINS/docker-compose.baixado"
curl -fsSL "https://github.com/docker/buildx/releases/download/{BUILDX_VERSAO}/buildx-{BUILDX_VERSAO}.linux-$ARQ" \\
  -o "$PLUGINS/docker-buildx.baixado"
# Rodam como root: só instala se o SHA-256 bater com o fixado no código
printf '%s  %s\\n' "$COMPOSE_SHA" "$PLUGINS/docker-compose.baixado" "$BUILDX_SHA" "$PLUGINS/docker-buildx.baixado" \\
  | sha256sum -c - || {{ rm -f "$PLUGINS"/*.baixado; exit 1; }}
mv "$PLUGINS/docker-compose.baixado" "$PLUGINS/docker-compose"
mv "$PLUGINS/docker-buildx.baixado" "$PLUGINS/docker-buildx"
chmod 755 "$PLUGINS/docker-compose" "$PLUGINS/docker-buildx"

# 2 GB de swap: folga para MySQL + MongoDB em 2 GB de RAM
if [ ! -f /swapfile ]; then
  dd if=/dev/zero of=/swapfile bs=1M count=2048 && chmod 600 /swapfile
  mkswap /swapfile && swapon /swapfile && echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

mkdir -p /opt/iosephus
cat > /opt/iosephus/atualizar.sh <<'FIM'
#!/bin/bash
# Baixa o código do último cdk deploy e sobe os containers. Os dados dos bancos (volumes) ficam.
set -euo pipefail
cd /opt/iosephus
URL=$(aws ssm get-parameter --region {regiao} --name {PARAMETRO_CODIGO} --query Parameter.Value --output text)
ZIP=$(mktemp)   # nome imprevisível: um /tmp/iosephus.zip fixo aceitaria symlink plantado
trap 'rm -f "$ZIP"' EXIT
aws s3 cp --region {regiao} --only-show-errors "$URL" "$ZIP"
rm -rf app.novo && mkdir app.novo && unzip -q "$ZIP" -d app.novo

# Segredos gerados aqui, uma única vez; nunca passam pelo CDK nem pelo Git
if [ ! -f .env ]; then
  umask 077
  {{
    for v in MYSQL_ROOT_PASSWORD MYSQL_APP_PASSWORD MONGO_ROOT_PASSWORD MONGO_APP_PASSWORD; do
      echo "$v=$(openssl rand -hex 24)"
    done
    echo "INGEST_API_KEY=$(openssl rand -hex 32)"
    echo "JWT_SECRET=$(openssl rand -hex 32)"
    echo "API_BIND=0.0.0.0"
    echo "API_PORT=80"
  }} > .env
fi
install -m 600 .env app.novo/.env   # já nasce 600 (cp + chmod deixava uma janela legível)

rm -rf app.anterior
[ -d app ] && mv app app.anterior
mv app.novo app
cd app
docker compose up -d --build --remove-orphans
docker image prune -f
echo "iosephus atualizado: $(date -u +%FT%TZ)"
FIM
chmod 700 /opt/iosephus/atualizar.sh
/opt/iosephus/atualizar.sh
"""
