#!/bin/bash
# Only for this disposable, network-disabled manager container.
set -euo pipefail
cp -a /var/ossec/data_tmp/exclusion/var/ossec/. /var/ossec/
/bin/bash /etc/cont-init.d/0-wazuh-init
chown -R wazuh:wazuh /var/ossec/etc/lists
