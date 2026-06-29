"""
TrustFeed — Entry Point
Run from CW/trustfeed/: python trustfeed.py --help
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import click
from cli.commands import ca, submit, verify, retract, export, status, dashboard

@click.group()
@click.version_option("1.0.0", prog_name="TrustFeed")
def cli():
    """
    TrustFeed — PKI-based cryptographic threat intelligence framework.

    Authenticate publishers · Sign IOCs · Verify feeds · Prevent replay attacks.
    """
    pass

cli.add_command(ca)
cli.add_command(submit)
cli.add_command(verify)
cli.add_command(retract)
cli.add_command(export)
cli.add_command(status)
cli.add_command(dashboard)

if __name__ == "__main__":
    cli()