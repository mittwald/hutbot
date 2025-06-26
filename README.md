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

This repository includes a Helm chart under `charts/hutbot` and a Helmfile configuration at `helmfile.yaml`.

Deploy the bot to your Kubernetes cluster using Helmfile:

```bash
helmfile sync
```

Before running, update `helmfile.yaml` with your Docker image repository, Slack tokens, and other configuration values.
