import oci
from oci.exceptions import ServiceError, ConfigFileNotFound, InvalidConfig
import sys
import os
import csv


# Static ANSI escape codes for colors
class Color:
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    RESET = "\033[0m"


def validate_oci_config(oci_config_path=None):
    """
    Validates and loads the OCI configuration from a specified file.

    Parameters:
    - oci_config_path: Optional; custom path to the OCI configuration file.

    Returns:
    The loaded OCI configuration.

    Exits the script with an error message if the configuration is invalid or missing.
    """
    if not oci_config_path:
        # Default OCI config path
        oci_config_path = os.path.expanduser("~/.oci/config")

    try:
        oci_config = oci.config.from_file(file_location=oci_config_path)
        oci.config.validate_config(oci_config)
        print(f"{Color.GREEN}OCI configuration file is valid.{Color.RESET}")
        return oci_config
    except ConfigFileNotFound:
        print(
            f"{Color.RED}OCI configuration file not found at '{oci_config_path}'.{Color.RESET}"
        )
        sys.exit(1)
    except InvalidConfig:
        print(
            f"{Color.RED}Invalid OCI configuration at '{oci_config_path}'.{Color.RESET}"
        )
        sys.exit(1)


def validate_nsg_ocid(config):
    """
    Validates the presence of the NSG OCID in the configuration.

    Parameters:
    - config: The configuration dictionary loaded from the config file.

    Exits the script with an error message if the NSG OCID is missing or blank.
    Otherwise, prints the NSG OCID and returns it.

    Returns:
    The NSG OCID if it exists in the configuration.
    """
    nsg_ocid = config.get("nsg_ocid", "").strip()
    if not nsg_ocid:
        print(
            f"{Color.RED}The NSG OCID is missing or blank in the configuration file.{Color.RESET}"
        )
        sys.exit(1)
    else:
        print(f"{Color.GREEN}Using NSG OCID: {Color.YELLOW}{nsg_ocid}{Color.RESET}")
        return nsg_ocid


def validate_rules_csv(rules_file_path):
    """
    Validates the rules CSV file for existence, readability, and basic format.

    Parameters:
    - rules_file_path: Path to the CSV file containing NSG rules.

    Exits the script with an error message if the file is invalid or missing.
    """
    required_columns = [
        "direction",
        "protocol",
        "cidr",
        "port_start",
        "port_end",
        "description",
    ]

    # Check if the file exists
    if not os.path.exists(rules_file_path):
        print(
            f"{Color.RED}Rules CSV file not found at '{rules_file_path}'.{Color.RESET}"
        )
        sys.exit(1)

    # Attempt to open and read the CSV file
    try:
        with open(rules_file_path, mode="r") as csv_file:
            csv_reader = csv.DictReader(csv_file)
            headers = csv_reader.fieldnames

            # Check for required columns
            missing_columns = [col for col in required_columns if col not in headers]
            if missing_columns:
                print(
                    f"{Color.RED}Missing columns in rules CSV file: {', '.join(missing_columns)}.{Color.RESET}"
                )
                sys.exit(1)

    except Exception as e:
        print(f"{Color.RED}Failed to read the rules CSV file: {e}{Color.RESET}")
        sys.exit(1)

    print(f"{Color.GREEN}Rules CSV file '{rules_file_path}' is valid.{Color.RESET}")


def create_security_rule(rule_config):
    """
    Creates a security rule detail object based on the provided rule configuration.

    Parameters:
    - rule_config: A dictionary containing the rule's configuration.

    Returns:
    An oci.core.models.AddSecurityRuleDetails object.
    """
    protocol_map = {"tcp": "6", "udp": "17", "icmp": "1", "all": "all"}
    protocol = protocol_map.get(
        rule_config["protocol"].lower(), rule_config["protocol"]
    )
    direction = rule_config["direction"].upper()

    options = {}
    if protocol in ["6", "tcp"]:
        options["tcp_options"] = oci.core.models.TcpOptions(
            destination_port_range=oci.core.models.PortRange(
                min=int(rule_config["port_start"]), max=int(rule_config["port_end"])
            )
        )
    elif protocol in ["17", "udp"]:
        options["udp_options"] = oci.core.models.UdpOptions(
            destination_port_range=oci.core.models.PortRange(
                min=int(rule_config["port_start"]), max=int(rule_config["port_end"])
            )
        )

    return oci.core.models.AddSecurityRuleDetails(
        direction=direction,
        protocol=protocol,
        description=rule_config["description"],
        is_stateless=False,
        source=rule_config["cidr"] if direction == "INGRESS" else None,
        destination=rule_config["cidr"] if direction == "EGRESS" else None,
        source_type="CIDR_BLOCK" if direction == "INGRESS" else None,
        destination_type="CIDR_BLOCK" if direction == "EGRESS" else None,
        **options,
    )


def add_security_rules_to_nsg(virtual_network_client, nsg_id, rules):
    """
    Attempts to add a batch of security rules to the specified NSG.

    Parameters:
    - virtual_network_client: The VirtualNetworkClient instance from the OCI SDK.
    - nsg_id: The OCID of the NSG to which the rules should be added.
    - rules: A list of AddSecurityRuleDetails objects.
    """
    try:
        virtual_network_client.add_network_security_group_security_rules(
            network_security_group_id=nsg_id,
            add_network_security_group_security_rules_details=oci.core.models.AddNetworkSecurityGroupSecurityRulesDetails(
                security_rules=rules
            ),
        )
        print(
            f"{Color.WHITE}{len(rules)}{Color.GREEN} rules added successfully.{Color.RESET}"
        )
    except ServiceError as e:
        print(f"{Color.RED}Failed to add rules: {e.message}{Color.RESET}")


def get_nsg_name(virtual_network_client, nsg_ocid):
    """
    Retrieves the display name of the specified NSG.

    Parameters:
    - virtual_network_client: The VirtualNetworkClient instance from the OCI SDK.
    - nsg_ocid: The OCID of the NSG.

    Returns:
    The display name of the NSG. Exits the script with an error if retrieval fails.

    Raises:
    - SystemExit: If unable to retrieve NSG details due to a ServiceError.
    """
    try:
        nsg_response = virtual_network_client.get_network_security_group(nsg_ocid)
        return nsg_response.data.display_name
    except ServiceError as e:
        print(f"{Color.RED}Failed to retrieve NSG details: {e.message}{Color.RESET}")
        print(
            f"{Color.YELLOW}Please check the NSG OCID ({Color.CYAN}{nsg_ocid}{Color.YELLOW}) and ensure you have permission to access it.{Color.RESET}"
        )
        sys.exit(1)


def confirm_changes(rule_count, nsg_name):
    """
    Prompts the user to confirm the addition of specified rules to the NSG.

    Parameters:
    - rule_count: The number of rules to be added.
    - nsg_name: The name of the NSG to which rules are to be added.

    Returns:
    True if the user confirms the action, False otherwise.
    """
    prompt_message = f"{Color.CYAN}Do you want to add these {Color.WHITE}{rule_count}{Color.CYAN} rules to NSG {Color.YELLOW}{nsg_name}{Color.CYAN}? (y/N): {Color.RESET}"
    response = input(prompt_message)
    return response.lower() == "y"


def batch_rules(rules, batch_size=25):
    """
    Divides a list of rules into smaller batches for processing.

    This function is useful for adhering to API request limits.

    Parameters:
    - rules: A list of rule objects to be added.
    - batch_size: The maximum number of rules each batch can contain.

    Yields:
    Lists of rules, each list containing up to batch_size rules.
    """
    for i in range(0, len(rules), batch_size):
        yield rules[i : i + batch_size]
