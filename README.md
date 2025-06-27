# hutbot Slack Bot

The hutbot is a simple Slack bot that monitors messages in a channel and automatically replies in a thread if no one reacts or responds to the message within a configurable time period (by default 30 minutes). The bot reminds channel members that a message has gone unanswered. Users can adjust both the waiting time and the reminder message directly within the channel.

## Step 1: Set Up the Slack App

1. **Create a New Slack App**

   - Go to [Slack API: Applications](https://api.slack.com/apps) and click **"Create New App"**.
   - Choose **"From scratch"** and give your app a name and select your workspace.

2. **Create an App-Level Token**

   - Go back to your app's settings.
   - Navigate to **"Basic Information"**.
   - Scroll down to **"App-Level Tokens"**.
   - Click **"Generate Token and Scopes"**.
   - Give it a name (e.g., `default`) and add the scope `connections:write`.
   - Click **"Generate"** and copy the token.

3. **Enable Socket Mode**

   - Go to **"Socket Mode"**.
   - Click on **"Enable Socket Mode"**.

4. **Add Required Permissions**

   - Navigate to **"OAuth & Permissions"** on the left sidebar.
   - Under **"Scopes"**, add the following bot token scopes:
     - `channels:history`
     - `channels:read`
     - `chat:write`
     - `reactions:read`
     - `im:history`
     - `im:read`
     - `im:write`
     - `mpim:history`
     - `mpim:read`
     - `mpim:write`
     - `groups:history`
     - `groups:read`
     - `usergroups:read`
     - `team:read`
     - `users.read`
     - `commands`

5. **Enable Event Subscriptions**

   - Go to **"Event Subscriptions"**.
   - Turn on **"Enable Events"**.
   - Under **"Subscribe to bot events"**, add:
     - `message.channels`
     - `reaction_added`
     - `message.groups`
     - `message.im`
     - `message.mpim`

6. **Install the App**

   - Go to **"Install App"**.
   - Click **"Install App to Workspace"** and authorize the app.
   - Copy the **Bot User OAuth Token**; you'll need it later.

8. **Run the App**

```
export SLACK_BOT_TOKEN='xoxb-your-bot-token'
export SLACK_APP_TOKEN='xapp-your-app-level-token'
pip install -r requirements.txt
python bot.py
```

   - See [Hutbot Slack App](https://api.slack.com/apps/A07RQ54Q5H9)
   - Hosted at `nexus-cli get projects p-knksv4 -olink`

9. **Invite Bot**

```
/invite @Hutbot
```

## Docker and Kubernetes Deployment

A GitHub Actions workflow automatically builds and publishes the Docker image to GitHub Container Registry on pushes to `main` and tags `v*.*.*`. You can pull the image with:

```bash
docker pull ghcr.io/mittwald/hutbot:latest
docker pull ghcr.io/mittwald/hutbot:<version>
```

This repository includes a Helm chart under `charts/hutbot` and a Helmfile configuration at `helmfile.yaml.gotmpl`.

Create a `.env` file in the project root (this file is ignored by git) with the following content:

```bash
export SLACK_BOT_TOKEN='<your bot token>'
export SLACK_APP_TOKEN='<your app-level token>'
export OPSGENIE_TOKEN='<your Opsgenie API token>'
export OPSGENIE_HEARTBEAT_NAME='<your Opsgenie heartbeat name>'
export EMPLOYEE_LIST_USERNAME='<your employee list username>'
export EMPLOYEE_LIST_PASSWORD='<your employee list password>'
export EMPLOYEE_LIST_MAPPINGS='<optional comma-separated mappings, e.g.: user1=alias1,user2=alias2>'
# To define netpol egress rules, you can set a space-separated list of <port>:<cidr[,cidr...]> entries:
export NETWORKPOLICY_RULES='443:192.168.0.15/32 80:10.0.0.0/24,10.0.1.0/24'
# To define host aliases for the pod (/etc/hosts entries), you can set a comma-separated list of <hostname>=<ip> entries:
export HOST_ALIASES='lb.mittwald.it=192.168.0.15'
```

Load the environment variables before deploying with Helmfile:

```bash
source .env
```

Before running, update `helmfile.yaml.gotmpl` with your Docker image repository and other configuration values.

Deploy the bot to your Kubernetes cluster using Helmfile:

```bash
helmfile sync
```

> **Note:** Helmfile uses Go templating to inject these variables and will error if any required environment variables are missing.
> Ensure you run `source .env` in the same shell as you execute `helmfile sync`.

### Persisting the Configuration File

Hutbot stores its channel configuration in a JSON file (`bot.json`) on a mounted volume. You can configure the persistence options in the Helm chart like this:

```yaml
persistence:
  enabled: true
  accessModes:
    - ReadWriteOnce
  size: 1Gi
  storageClass: "<your-storage-class>"
  mountPath: "/data"
```

When persistence is enabled (default: `true`), the chart will automatically set the `HUTBOT_CONFIG_FILE` environment variable so Hutbot reads and writes its config from the mounted volume (at `<mountPath>/bot.json`).
Additionally, Hutbot stores its employee list cache in a JSON file (`employees.json`) on the same mounted volume. The chart will set the `HUTBOT_EMPLOYEE_CACHE_FILE` environment variable so Hutbot reads and writes its employee cache from the mounted volume (at `<mountPath>/employees.json`).

> **Note:** The PersistentVolumeClaim created by this chart is annotated with `helm.sh/resource-policy: keep`, so it will not be deleted when you run `helm uninstall`. You can manually remove the PVC (and its underlying volume) by running `kubectl delete pvc <release-name>-pvc`. Keep in mind that if your StorageClass has a `Delete` reclaimPolicy, the underlying storage will still be deleted by the provisioner; to prevent this, use a StorageClass with `ReclaimPolicy: Retain`.

If you override values via environment variables in Helmfile, you can configure persistence like this:

```bash
export PERSISTENCE_ENABLED=true
export PERSISTENCE_SIZE=1Gi
export PERSISTENCE_STORAGE_CLASS=<your-storage-class>
export PERSISTENCE_MOUNT_PATH=/data
# To define netpol egress rules, you can set a space-separated list of <port>:<cidr[,cidr...]> entries:
export NETWORKPOLICY_RULES='443:192.168.0.15/32 80:10.0.0.0/24,10.0.1.0/24'
# To define host aliases for the pod (/etc/hosts entries), you can set a comma-separated list of <hostname>=<ip> entries:
export HOST_ALIASES='lb.mittwald.it=192.168.0.15'
helmfile sync
```
