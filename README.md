# Barton - Bulk Add Rules To OCI NSG

This project provides a Python script named `barton.py` for adding rules to Network Security Groups (NSG) in Oracle Cloud Infrastructure (OCI). It enables users to add NSG rules in bulk from a CSV file, incorporating validations for both the OCI configuration and the rules file format.

![BartonLogoHorizontal](https://github.com/tristanbob/barton/assets/8879811/b4988dd3-b238-4edd-857c-939aa8953218)

## Features

- Validate configuration and NSG rules CSV file
- Display planned NSG rule additions with colored output for clarity.
- Confirm with the user before applying changes to the NSG.
- Add NSG rules in batches to accommodate API request limits.

## Prerequisites

- Python 3.6 or later.

## Setup

1. Clone this repository to your local machine.

2. Ensure you have Python and pip installed on your system.

3. Install the required Python dependencies by running the following command in the project directory:

   ```
   pip install -r requirements.txt
   ```

4. Set up your OCI configuration if you haven't already. This involves creating a configuration file that the OCI Python SDK can use to authenticate your requests. Run the following command and follow the prompts:

   ```
   oci setup config
   ```

   This command will create a `.oci` directory in your home directory with a `config` file inside. For more details on configuring the OCI CLI, refer to the [official documentation](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm).

5. Prepare your NSG rules in a CSV file following the specified format:

   ```
   direction,protocol,cidr,port_start,port_end,description
   INGRESS,tcp,192.168.1.0/24,80,80,Allow HTTP traffic
   EGRESS,udp,0.0.0.0/0,53,53,Allow DNS queries
   ```

6. Edit the `config.yaml` file to include your NSG OCID and the path to your rules CSV file.

## Usage

Run the script using the following command:

```
python barton.py
```

The script will validate the OCI config and the rules file, then display the planned actions. User must confirm to apply the changes.

## Configuration

The `config.yaml` file should include:

- `nsg_ocid`: The OCID of your target NSG.
- `nsg_rules_file`: Path to your NSG rules CSV file.
- `batch_size`: (Optional) Number of rules to add per batch. Default is 25.

## Sample output

![barton-example](https://github.com/tristanbob/barton/assets/8879811/3db992cb-d503-45d2-8c6d-3481b133cc93)

```
> python .\barton.py
Using NSG OCID: ocid1.networksecuritygroup.oc1.phx.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Rules CSV file 'example_nsg_rules.csv' is valid.
OCI configuration file is valid.
Planned actions for NSG tristans-automation-testing-nsg:
- Allow protocol TCP from 10.0.0.0/16 on ports 80-80 (Allow HTTP traffic)
- Allow protocol UDP from 10.0.0.0/16 on ports 53-53 (Allow DNS queries)
- Allow protocol ICMP from 0.0.0.0/0 on ports - (Allow ICMP (e.g., ping))
- Allow protocol ALL to 0.0.0.0/0 on ports - (Allow all outbound traffic)
Do you want to add these 4 rules to NSG tristans-automation-testing-nsg? (y/N): y
4 rules added successfully.
All rules have been successfully added to the NSG.
```

## Contributing

Contributions are welcome! Feel free to submit pull requests or open issues to suggest improvements or add new features.

## License

This project is open-source and available under the [MIT License](LICENSE).
