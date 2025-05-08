## Warning, read this before you start!
You are responsible for laboratory setup and administration.

## About the files
* **dd-helm.yaml** (Configuration to deploy Datadog with APM, Networking, Process and all **Security features**)
* **eksctl-sample.yaml** (file to create a EKS cluster in AWS, you need an admin credencial in AWS to create the cluster)

If you setup the [CSM](https://docs.datadoghq.com/security/cloud_security_management/setup) and [Datadog Cloud SIEM](https://docs.datadoghq.com/security/cloud_siem/guide/aws-config-guide-for-cloud-siem/) you can see Security Signals related to eksct and misconfiguration
  
## How to use EKSCTL
* [The official CLI for Amazon EKS](https://eksctl.io/)

## How to install DD in Kubernetes env
[Installing Datadog on K8S via HELM](https://docs.datadoghq.com/containers/kubernetes/installation?tab=helm)

or follow this steps

**kubectl quick reference**
[Quick Reference](https://kubernetes.io/docs/reference/kubectl/quick-reference)

```k create namespace datadog```

```helm repo add datadog https://helm.datadoghq.com```

```helm repo update```

```kubectl create secret generic datadog-secret --from-literal api-key=put_your_api_key -n datadog```

```helm install datadog-agent -f dd-helm.yaml datadog/datadog -n datadog ```

if works you should see the pods!

![image](https://github.com/user-attachments/assets/38878080-f8d1-46b1-b0c0-6deb7d8d9c8a)


