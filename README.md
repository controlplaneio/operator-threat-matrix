# Operator Threat Matrix

## Table of Contents
- [Background](#background)
    - [References](#references)
- [Components](#components)
- [Threat Matrix](#threat-matrix)
    - [Techniques and Mitigations](#techniques-and-mitigations)

## Background
Kubernetes Operators are an extension of the Kubernetes API and reduce repetitive, manual, human driven tasks by defining custom resources. The Threat Matrix provides a [MITRE ATT&CK](https://attack.mitre.org/) inspired view for Kubernetes Operators.

### References
* [CNCF-TAG Operator Working Group Operator Whitepaper](https://github.com/cncf/tag-app-delivery/blob/eece8f7307f2970f46f100f51932db106db46968/operator-wg/whitepaper/Operator-WhitePaper_v1-0.md)

* [Google Best Practices For Building Kubernetes Operators](https://cloud.google.com/blog/products/containers-kubernetes/best-practices-for-building-kubernetes-operators-and-stateful-apps)

* [Microsoft Threat Matrix for Kubernetes 2021](https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/)

* [Microsoft Threat Matrix for Kubernetes Update 2020](https://www.microsoft.com/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes/)

* [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)

## Operator Components
Kubernetes Operators introduces several key components to a cluster, which include:

1. Custom Resource Definitions (CRDs)
2. Custom Controller
3. Operator Namespace*
4. Service Account*
5. Logging and Metrics

> \* Operators can utilise existing cluster resources such as initial namespaces, serviceaccounts and roles such as cluster-admin.

## Threat Matrix
 Kubernetes Operators are not limited to modifying Kubernetes resources; an Operator can reconcile and manage resources outside of the cluster, such as those of the Cloud Provider. Thus, it is important to highlight threats which are only applicable to Operators with a external scope. The scope is represented in the following way:

Internal Scope = Kubernetes bound resources (namespaced, clusterwide or multi-cluster bound resources)

**External Scope** = Resources outside of the Kubernetes cluster (e.g. Cloud Provider)

![Operator Threat Matrix](images/operator-threat-matrix.svg)

## Techniques and Mitigations

### Initial Access

| Techniques | Description |
|-----|-----|
| Using Cloud Credentials | Compromised Cloud credentials can be used to access a Kubernetes Operator. Depending on the scope of the Operator, adversaries may have access to specific resources in a namespace, complete cluster-wide resources or external resources.|
| Compromised Image in Registry | Kubernetes Operators are fundamentally a customised controller bundled into a container image which is deployed onto the cluster. Generally, a container image can be compromised in two places, accessing the source code repository for the controller and accessing the container image registry. Adversaries with access to the source code repository can modify the controller code to perform malicious actions on the cluster. Adversaries who obtain access to private registry can plant their own compromised image. Operators can also be pulled from public regisities which may contain malicious code. Common public operators can be pulled from https://operatorhub.io/ that are maintained by the community which could be susceptible to supply chain attacks. Building images based on untrusted base images can introduce vulnerable or malicious code. |
| Kubeconfig File | The kubeconfig file contains credentials for accessing a Kubernetes cluster and by proxy a Kubernetes Operator. Adversaries may obtain the kubeconfig file via a users compromised device |

### Execution

| Techniques | Description |
|-----|-----|
| Exec into container | Adversaries which have obtained access to a role with "pods/exec" permissions will be able to execute malicious commands in the Operator container. |
| New Container | Adversaries may leverage the permissions of an Operator to deploy a kubernetes native resource (such as pod) or custom resource (such as another Operator) to run malicious code in the cluster. |
| Sidecar Injection | A typical use case for an Operator is to deploy and manage a sidecar container to provide supporting functionality alongside an application container. This could be TLS certificates, service-mesh proxies or storage interface. Adversaries can leverage the permissions of an Operator to conceal malicious activity by injecting a malicious sidecar container into an authorised pod or deployment. |
| OLM Automatic Install | The Operator Lifecycle Manager (OLM) allows users to maintain up to date Operators within the cluster. Operators can be automatically rolled out based on the subscribed channel and the skipping the designated install plan. Adversaries can abuse this functionality to automatically deploy a malicious Operator bypassing any formal release and review. |
| **Cloud Instance** | Adversaries can abuse an Operators Cloud permissions to execute a malicious script or scheduled task on a Cloud instance. This could be full instance, containerised workload or serverless execution. |

### Persistence

| Techniques | Description |
|-----|-----|
| Malicious Operator | An Operator reconciles custom resources internally or externally to the cluster. Adversaries could leverage the controller functionality to persist the execution of malicious code within the cluster, ensuring pods or hidden resources are always running. Additionally a malicious Operator could self replicate across the cluster ensuring the Operator persists upon deletion. |
| Backdoor Container | Adversaries with access to an Operator with cluster-wide permissions can ensure a malicious pod is running on the cluster as well as utilise a DaemonSet to ensure all nodes run a copy of the pod. |
| Write Host Path Mount | A compromised Operator with permissions to create pods and persistent volume claims can mount a writable host volume to a container. This allows data to persist on the host between workload execution. |
| Malicious admission controller | An Operator could be used to manage admission controllers for the cluster. Adversaries can use the Operator to create or modify an admission controller to perform malicious actions such as intercepting requests to the Kubernetes API or recording secrets. |
| OLM Catalog | The Operator Lifecycle Manager (OLM) catalog allows users to manage a collection of Operators to be installed on the cluster. The catalog source custom resource defintion accepts a container image reference for the bundle of Operators (the catalog is packaged within the container along with the metadata for the OLM to manage each Operator). Adversaries with access to this catalog can tamper the container image reference to include a bundle with an additional malicious Operator. |
| **Access Cloud Resources** | Adversaries can abuse an Operators Cloud permissions to persist malicious images or code within a Cloud Provider. As the Operator will reconcile external resources, it can persist any compromised or malicious instances within the Cloud Provider. |

### Privilege Escalation

| Techniques | Description |
|-----|-----|
| Privileged Container | An Operator can be deployed with privileged capabilities allowing access to host level processes. Adversaries which gain access to a privileged Operator can break out of the container "boundary" and access the underlying host. |
| Cluster-Admin Binding | Operators commonly perform administrative functions inside and/or outside of the Kubernetes cluster. It is not uncommon for an Operator to be allocated cluster admin (or equivalent) permissions to perform the necessary actions against resources. Adversaries can abuse cluster admin permissions assigned to the Operator or permissions which are able to bind cluster admin (or equivalent) to a role, to obtain full access to cluster resources. |
| Mount Host Path | An Operator which has been mounted to an underlying hosts path can be abused by an adversary to access host level resources. |
| **Access Cloud Resources** | Operators with overly permissive access to external resources may allow an adversary to abuse an assigned role to escape cluster restrictions. |

### Defense Evasion

| Techniques | Description |
|-----|-----|
| Clear Container Logs | An Operator can be deployed with permissions to modify pod or host logs. Adversaries can abuse these permissions to remove malicious activity from the Operators log or pods which are under the control of the Operator. |
| Delete Kubernetes Events | Kubernetes events capture state changes or errors across the cluster and are API objects stored on the Kubernetes API Server. An Operator with access to event resources can be abused by adversaries to remove sensitive actions to avoid detection. |
| Use Another Operator | Adversaries could abuse an Operators privileges to modify another deployed Operator to mask malicious actions and deceive security operations and incident response. |
| **Disable Cloud Logging** | Adversaries can exploit operators with permissions to provision and modify cloud logging, or individual cloud services (such as S3 Buckets) to disable logging for the entire cloud account or specific service (e.g. S3:PutBucketLogging).  |

### Credential Access

| Techniques | Description |
|-----|-----|
| List Kubernetes Secrets | Kubernetes Secret is an object which can store sensitive data such as access credentials. An Operator with permissions to list secrets can be abused by adversaries to access sensitive credentials. |
| Access Operator Service Account | The Operator service account (SA) provides access to the Kubernetes API Server to configure Kubernetes native resources or custom resources. Adversaries with access to the Operator Pod can steal the SA token and perform actions which are bound to the permissions of the SA. |
| **Access Cloud Credentials** | An Operator which externally accesses Cloud resources can be configured with a K8s service account (SA) role bound to a Cloud Provider SA. Adversaries with access to the Operator can steal the K8s SA token and thus perform actions which are bound to the permissions of the Cloud SA. |

### Discovery

| Techniques | Description |
|-----|-----|
| Access the Kubernetes API Server | All Operators require access to the Kubernetes API Server to reconcile custom resources in the cluster. Adversaries can abuse an Operator access to the Kubernetes API Server to enumerate cluster services such as pods and secrets |
| Network Mapping | Adversaries with Operator access can perform network scans to discover open ports and running application vulnerabilities. Without network policies, there are no restrictions applied to pod communication within the cluster. |
| **Cloud Infrastructure Discovery** | An externally scoped Operator can allow adversaries to discover resources within an infrastructure-as-a-service (IaaS) environment. This includes running compute instances, storage and database services. |
| **Cloud Storage Object Discovery** | An externally scoped Operator can allow adversaries to enumerate data objects within Cloud storage services. This includes sensitive data, instance or container images and logs.|

### Lateral Movement

| Techniques | Description |
|-----|-----|
| Kubernetes Service Accounts | An Operator may require access to Kubernetes service accounts to completely manage resources remotely (e.g. GitOps). Adversaries can abuse these permissions to access existing Kubernetes Service Accounts which may allow specific cluster resources.  |
| Cluster Internal Networking | Adversaries with Operator access can attempt to pivot to another pod which are exposed within the cluster network. |
| Writable Host Volume Mounts | An Operator which has been mounted to an underlying hosts path can be abused by an adversary to access host level resources. |
| **Access Cloud Resources** | An Operator with external access can be abused by Adversaries to pivot outside of the cluster and attack accessible Cloud resources. |

### Collection

| Techniques | Description |
|-----|-----|
| **Data From Cloud Storage Object** | An externally scoped Operator can allow adversaries to access data objects within Cloud storage services. |

### Exfiltration

| Techniques | Description |
|-----|-----|
| **Transfer Data to Cloud Account** | An externally scoped Operator provides a required route to Cloud resources. If external traffic restrictions are not applied to the Cloud Provider (e.g. DNSSEC, Security Groups, etc) adversaries can abuse connectivity to transfer sensitive data outside of an organisations domain to another attack owned domain within the same Cloud Provider.|

### Impact

| Techniques | Description |
|-----|-----|
| Data Destruction | A primary use case for Operators is managing stateful applications utilising the reconcilation functionality provided by Kubernetes to bootstrap, update and backup datastores. Adversaries with Operator access may attempt to destroy data held in managed stateful applications as well as cluster related data (e.g. deployments and configuration) or data stored within Cloud resource. |
| Resource Hijacking | An Operator can be abused by Adversaries to hijack cluster resources (e.g. Pods, Service Accounts) or Cloud resources such as executing malicious code on running instances.|
| Denial of Service | Kubernetes Operators have the potential to create large amounts of custom resources which are continuously reconciled. Without resource limits configured, Adversaries can use an Operator to exhaust cluster resources causing a denial of service condition. If the Operator Service Account was overly privileged, it may modify network policies to prevent pod to pod communications, remove Kubernetes Secrets preventing pod access or modify admission controls to prevent the deployment of new resources. |
| **Data Encryption for Impact** | An Operator managing a stateful application may have access to Cloud key management service to encrypt and decrypt hosted data. Adversaries may abuse the Operator permissions to create a new key, encrypt any objects held and destroy encryption key to prevent users or systems from accessing the stored data. Additionally, the data could be held at ransom until the Adversary is paid to decrypt it. |