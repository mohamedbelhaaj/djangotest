import boto3
from botocore.exceptions import ClientError
import logging

logger = logging.getLogger(__name__)

class AWSManager:
    """
    Gère toutes les interactions avec l'API AWS (EC2, WAF, etc.)
    en utilisant les credentials de l'objet AWSConfiguration.
    """
    def __init__(self, aws_config):
        """
        Initialise les clients Boto3 avec les clés de la base de données.
        """
        self.config = aws_config
        self.session = boto3.Session(
            aws_access_key_id=self.config.aws_access_key,
            aws_secret_access_key=self.config.aws_secret_key,
            region_name=self.config.aws_region
        )
        
        try:
            self.ec2 = self.session.client('ec2')
            self.wafv2 = self.session.client('wafv2')
            self.network_firewall = self.session.client('network-firewall')
            self.cloudwatch = self.session.client('logs')
            # Ajoutez d'autres clients au besoin (cloudfront, alb, iam)
            
            logger.info(f"Clients Boto3 initialisés pour la région {self.config.aws_region}")
        except Exception as e:
            logger.error(f"Échec de l'initialisation des clients Boto3 : {e}")
            self.ec2 = None

    
    def test_credentials(self):
        """
        Tente une simple commande en lecture seule pour vérifier les identifiants.
        """
        if not self.ec2:
            return {'success': False, 'error': 'Client EC2 non initialisé.'}
        
        try:
            # Tente de décrire les régions (une commande simple)
            self.ec2.describe_regions()
            logger.info("Test de connexion AWS réussi.")
            return {'success': True, 'message': 'Connexion AWS réussie.'}
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code')
            if error_code == 'AuthFailure':
                logger.error(f"Test de connexion AWS échoué : Authentification échouée. Vérifiez les clés API.")
                return {'success': False, 'error': 'Authentification échouée. Vérifiez vos Clés AWS.'}
            logger.error(f"Test de connexion AWS échoué : {e}")
            return {'success': False, 'error': str(e)}
        except Exception as e:
            logger.error(f"Erreur inattendue lors du test de connexion AWS : {e}")
            return {'success': False, 'error': str(e)}

    # ===================================================================
    # FONCTIONNALITÉ 1 : BLOQUER/AUTORISER IP (Security Group)
    # ===================================================================
    def _modify_security_group_ingress(self, action, ip_address, description=""):
        """Fonction privée pour bloquer (revoke) ou autoriser (authorize) une IP."""
        if not self.ec2:
            return {'success': False, 'error': 'Client EC2 non initialisé.'}
        
        if '/' not in ip_address:
            ip_cidr = f"{ip_address}/32"
        else:
            ip_cidr = ip_address

        try:
            ip_permission = {
                'IpProtocol': '-1', # Tous
                'FromPort': -1,
                'ToPort': -1,
                'IpRanges': [{'CidrIp': ip_cidr, 'Description': description}]
            }
            
            if action == 'block':
                # Pour "bloquer" dans un SG, nous RÉVOQUONS la permission d'ENTRÉE (Ingress)
                logger.info(f"Blocage (Revoke Ingress) de {ip_cidr} dans le SG {self.config.security_group_id}...")
                self.ec2.revoke_security_group_ingress(
                    GroupId=self.config.security_group_id,
                    IpPermissions=[ip_permission]
                )
                msg = f"IP {ip_cidr} bloquée (Ingress révoqué) dans le SG {self.config.security_group_id}."

            elif action == 'allow':
                # Pour "autoriser", nous AUTORISONS la permission d'ENTRÉE (Ingress)
                logger.info(f"Autorisation (Authorize Ingress) de {ip_cidr} dans le SG {self.config.security_group_id}...")
                self.ec2.authorize_security_group_ingress(
                    GroupId=self.config.security_group_id,
                    IpPermissions=[ip_permission]
                )
                msg = f"IP {ip_cidr} autorisée (Ingress autorisé) dans le SG {self.config.security_group_id}."

            logger.info(msg)
            return {'success': True, 'message': msg}
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if 'Duplicate' in error_code or 'Exists' in error_code:
                msg = f"La règle pour {ip_cidr} existe déjà."
                logger.warning(msg)
                return {'success': True, 'message': msg} # Ce n'est pas un échec
            if 'NotFound' in error_code:
                msg = f"La règle pour {ip_cidr} n'a pas été trouvée (lors de la révocation)."
                logger.warning(msg)
                if action == 'block':
                     return {'success': True, 'message': f"IP {ip_cidr} déjà bloquée (règle non trouvée)."}
            logger.error(f"Erreur Boto3 lors de la modification du SG : {e}")
            return {'success': False, 'error': str(e)}
        except Exception as e:
            logger.error(f"Erreur inattendue lors de la modification du SG : {e}")
            return {'success': False, 'error': str(e)}

    def block_ip_in_security_group(self, ip_address, description):
        """Action publique pour bloquer une IP."""
        return self._modify_security_group_ingress('block', ip_address, description)

    def allow_ip_in_security_group(self, ip_address, description):
        """Action publique pour autoriser une IP."""
        return self._modify_security_group_ingress('allow', ip_address, description)

    # ===================================================================
    # FONCTIONNALITÉS STUBS (Vides, à implémenter)
    # ===================================================================

    def block_ip_in_waf(self, ip_address, ip_set_name='default_ip_set', scope='REGIONAL'):
        """Bloque une IP dans un IP Set WAF v2."""
        logger.warning("Fonction 'manage_waf_rules' non implémentée.")
        # Logique :
        # 1. Obtenir l'IP Set (self.wafv2.get_ip_set) pour avoir le LockToken
        # 2. Mettre à jour l'IP Set (self.wafv2.update_ip_set) avec l'action 'INSERT'
        return {'success': False, 'error': 'Fonction WAF non implémentée.'}

    def edit_nacl_rules(self, nacl_id, rule_number, ip_cidr, action='add_deny_inbound'):
        """Modifie les entrées NACL."""
        logger.warning("Fonction 'edit_nacl_rules' non implémentée.")
        # Logique : self.ec2.create_network_acl_entry ou replace_network_acl_entry
        return {'success': False, 'error': 'Fonction NACL non implémentée.'}
        
    def update_network_firewall_policy(self, policy_arn, rule_group_arn):
        """Gère les politiques du Network Firewall."""
        logger.warning("Fonction 'update_network_firewall_policy' non implémentée.")
        # Logique : self.network_firewall.update_firewall_policy
        return {'success': False, 'error': 'Fonction Network Firewall non implémentée.'}

    def set_geo_blocking(self, waf_arn, country_codes_to_block):
        """Configure le Géo-blocage WAF."""
        logger.warning("Fonction 'set_geo_blocking' non implémentée.")
        # Logique : Mettre à jour une Rule Group WAF avec une déclaration GeoMatch
        return {'success': False, 'error': 'Fonction Géo-blocage non implémentée.'}

    def set_rate_limit_rule(self, waf_arn, limit=1000):
        """Configure une règle de limitation de débit WAF."""
        logger.warning("Fonction 'set_rate_limit_rule' non implémentée.")
        # Logique : Mettre à jour une Rule Group WAF avec RateBasedStatement
        return {'success': False, 'error': 'Fonction Limitation de Débit non implémentée.'}

    def isolate_instance(self, instance_id):
        """Isole une instance EC2 (action en un clic)."""
        logger.warning("Fonction 'isolate_instance' non implémentée.")
        # Logique :
        # 1. self.ec2.modify_instance_attribute (changer les Security Groups)
        # 2. self.elbv2.deregister_targets (si derrière un ALB)
        return {'success': False, 'error': 'Fonction Isoler Instance non implémentée.'}

    def get_audit_trail(self, resource_type, resource_name):
        """Récupère les logs d'audit CloudTrail."""
        logger.warning("Fonction 'get_audit_trail' non implémentée.")
        # Logique : self.cloudtrail.lookup_events
        return {'success': False, 'error': 'Fonction Audit Trail non implémentée.'}

    def get_vpc_flow_logs(self, log_group_name, filter_pattern):
        """Interroge les VPC Flow Logs via CloudWatch Logs."""
        logger.warning("Fonction 'get_vpc_flow_logs' non implémentée.")
        # Logique : self.cloudwatch.filter_log_events
        return {'success': False, 'error': 'Fonction VPC Flow Logs non implémentée.'}