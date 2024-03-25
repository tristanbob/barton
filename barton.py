# Barton - Bulk Add Rules To OCI NSG
#
# Description: This script reads a CSV file with security rules and adds them to an NSG in Oracle Cloud Infrastructure.
#
# The script requires a YAML configuration file with the following parameters:
# - nsg_ocid: The OCID of the NSG where the rules will be added.
# - nsg_rules_file: The path to the CSV file with the security rules.
# - batch_size: The number of rules to add in each batch (default is 25).
# - oci_config_file: The path to the OCI configuration file (default is ~/.oci/config).
#
# The CSV file should have the following columns:
# - direction: The direction of the rule (INGRESS or EGRESS).
# - protocol: The protocol of the rule (tcp, udp, icmp, etc.).
# - cidr: The CIDR block to allow traffic from/to.
# - port_start: The start port of the rule.
# - port_end: The end port of the rule.
# - description: A description of the rule.
#
# Example CSV line:
# ingress,tcp,10.0.0.0/16,80,80,"Allow HTTP traffic"
#
# Usage: python barton.py
#

import oci  # Import the Oracle Cloud Infrastructure SDK for Python
import csv  # Import the CSV module to read CSV files
import argparse  # Import the argparse module to parse command-line arguments
import yaml  # Import the YAML module to read the configuration file
import sys  # Import the sys module to use sys.exit()
from utils import (  # Import helper functions from the utils module
    Color,
    create_security_rule,
    add_security_rules_to_nsg,
    get_nsg_name,
    confirm_changes,
    batch_rules,
    validate_oci_config,
    validate_rules_csv,
    validate_nsg_ocid,
)

script_version = "1.0"

parser = argparse.ArgumentParser(
    description="Add security rules to an NSG in OCI from a CSV file.",
    epilog="""CSV file format: direction, protocol, cidr, port_start, port_end, description
Example CSV line: INGRESS,tcp,192.168.1.0/24,80,80,Allow HTTP traffic from Office Network""",
    formatter_class=argparse.RawTextHelpFormatter,
)
parser.add_argument(
    "-c", "--config", default="config.yaml", help="Path to the YAML configuration file."
)
parser.add_argument("--version", action="version", version=f"%(prog)s {script_version}")
args = parser.parse_args()

# Load configuration
with open(args.config, "r") as config_file:
    config = yaml.safe_load(config_file)

# Load and validate the NSG OCID from the configuration
nsg_ocid = validate_nsg_ocid(config)

# Validate the rules CSV file
rules_file_path = config["nsg_rules_file"]
validate_rules_csv(rules_file_path)

batch_size = config.get("batch_size", 25)

# Load the OCI configuration file path
oci_config_file = config.get("oci_config_file")

# Validate and load the OCI configuration
oci_config = validate_oci_config(oci_config_path=oci_config_file)

virtual_network_client = oci.core.VirtualNetworkClient(oci_config)

if __name__ == "__main__":
    rules_config = []
    with open(rules_file_path, mode="r") as csv_file:
        csv_reader = csv.DictReader(csv_file)
        for row in csv_reader:
            rules_config.append(row)

    nsg_name = get_nsg_name(virtual_network_client, nsg_ocid)
    total_rules = len(rules_config)

    # Display planned actions before asking for confirmation
    print(f"{Color.CYAN}Planned actions for NSG {Color.YELLOW}{nsg_name}:{Color.RESET}")
    for rule in rules_config:
        direction_word = "to" if rule["direction"] == "egress" else "from"
        print(
            f"- Allow protocol {Color.BLUE}{rule['protocol'].upper()}{Color.RESET} "
            f"{Color.MAGENTA}{direction_word}{Color.RESET} {Color.GREEN}{rule['cidr']}{Color.RESET} "
            f"on ports {Color.RED}{rule['port_start']}-{rule['port_end']}{Color.RESET} "
            f"({Color.CYAN}{rule['description']}{Color.RESET})"
        )

    # Ask for confirmation once, after displaying all rules
    if confirm_changes(total_rules, nsg_name):
        for batch in batch_rules(rules_config, batch_size):
            security_rules = [create_security_rule(rule) for rule in batch]
            add_security_rules_to_nsg(virtual_network_client, nsg_ocid, security_rules)
        print(
            f"{Color.GREEN}All rules have been successfully added to the NSG.{Color.RESET}"
        )
    else:
        print(f"{Color.RED}No changes were applied.{Color.RESET}")
