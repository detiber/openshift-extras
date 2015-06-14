import click
import re
from ooinstall.ansible_wrapper import install_transactions
from ooinstall.config.oo_config import OOConfig

def validate_ansible_dir(path):
    if not path:
        raise click.BadParameter('A valid ansible path must be provided')
    return path

def is_valid_hostname(hostname):
    print hostname
    if not hostname or len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1] # strip exactly one dot from the right, if present
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

def validate_hostname(ctx, param, hosts):
    for hostname in hosts:
        if not is_valid_hostname(hostname):
            raise click.BadParameter('"{}" appears to be an invalid hostname. Please double-check this value and re-enter it.'.format(hostname))
    return hosts

def validate_prompt_hostname(hostname):
    if '' == hostname or is_valid_hostname(hostname):
        return hostname
    raise click.BadParameter('"{}" appears to be an invalid hostname. Please double-check this value and re-enter it.'.format(hostname))

def get_hosts(hosts):
    click.echo('Please input each target host, followed by the return key. When finished, simply press return on an empty line.')
    while True:
        hostname = click.prompt('hostname/IP address', default='', value_proc=validate_prompt_hostname)
        if '' == hostname:
            break
        hosts.append(hostname)
    hosts = list(set(hosts)) # uniquify
    return hosts

def list_hosts(hosts):
    hosts_idx = range(len(hosts))
    for idx in hosts_idx:
        click.echo('   {}: {}'.format(idx, hosts[idx]))

def delete_hosts(hosts):
    while True:
        list_hosts(hosts)
        del_idx = click.prompt('Select host to delete, y/Y to confirm, or n/N to add more hosts', default='n')
        try:
            del_idx = int(del_idx)
            hosts.remove(hosts[del_idx])
        except IndexError:
            click.echo("\"{}\" doesn't match any hosts listed.".format(del_idx))
        except ValueError:
            try:
                response = del_idx.lower()
                if response in ['y', 'n']:
                    return hosts, response
                click.echo("\"{}\" doesn't coorespond to any valid input.".format(del_idx))
            except AttributeError:
                click.echo("\"{}\" doesn't coorespond to any valid input.".format(del_idx))
    return hosts, None

def collect_hosts():
    hosts = []
    while True:
        get_hosts(hosts)
        hosts, confirm = delete_hosts(hosts)
        if 'y' == confirm:
            break
    return hosts

@click.command()
@click.option('--configuration', '-c',
              type=click.Path(file_okay=True,
                              dir_okay=False,
                              writable=True,
                              readable=True),
              default=None)
@click.option('--ansible-directory',
              '-a',
              type=click.Path(exists=True,
                              file_okay=False,
                              dir_okay=True,
                              writable=True,
                              readable=True),
              envvar='OO_ANSIBLE_DIRECTORY')
@click.option('--host', '-h', multiple=True, callback=validate_hostname)
def main(configuration, ansible_directory, host):
    oo_cfg = OOConfig(configuration)
    print oo_cfg.settings
    # TODO - Config settings precedence needs to be handled more generally
    if not ansible_directory:
        ansible_directory = oo_cfg.settings.get('ansible_directory', '')
    else:
        oo_cfg.settings['ansible_directory'] = ansible_directory
    validate_ansible_dir(ansible_directory)
    install_transactions.set_config(oo_cfg)
    if not host:
        if oo_cfg.settings.get('hosts'):
            host = oo_cfg.settings['hosts']
        else:
            host = collect_hosts()
    oo_cfg.settings['hosts'] = host
    oo_cfg.save_to_disk()
    install_transactions.default_facts(host)

if __name__ == '__main__':
    main(None, "../../../../../openshift-ansible", None)
