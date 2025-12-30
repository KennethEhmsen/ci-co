/**
 * Kubernetes Security Module (v1.28.0)
 *
 * Provides Kubernetes security scanning and analysis including:
 * - Cluster-wide security scanning
 * - Namespace-specific scanning
 * - Security context analysis
 * - RBAC auditing
 * - Network policy analysis
 */

import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import { randomUUID } from "crypto";

const execFileAsync = promisify(execFile);

// =============================================================================
// Types
// =============================================================================

export type K8sResourceType =
  | "Pod"
  | "Deployment"
  | "StatefulSet"
  | "DaemonSet"
  | "ReplicaSet"
  | "Job"
  | "CronJob"
  | "Service"
  | "Ingress"
  | "ConfigMap"
  | "Secret"
  | "ServiceAccount"
  | "Role"
  | "ClusterRole"
  | "RoleBinding"
  | "ClusterRoleBinding"
  | "NetworkPolicy"
  | "PodSecurityPolicy"
  | "ResourceQuota"
  | "LimitRange";

export type K8sSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type K8sMisconfigCategory =
  | "security_context"
  | "resource_limits"
  | "network"
  | "rbac"
  | "secrets"
  | "image"
  | "pod_security"
  | "compliance";

export interface K8sMisconfiguration {
  id: string;
  title: string;
  description: string;
  severity: K8sSeverity;
  category: K8sMisconfigCategory;
  resourceType: K8sResourceType;
  resourceName: string;
  namespace: string;
  remediation: string;
  references: string[];
}

export interface K8sSecurityContext {
  runAsNonRoot?: boolean;
  runAsUser?: number;
  runAsGroup?: number;
  fsGroup?: number;
  privileged?: boolean;
  allowPrivilegeEscalation?: boolean;
  readOnlyRootFilesystem?: boolean;
  capabilities?: {
    add?: string[];
    drop?: string[];
  };
  seccompProfile?: {
    type: string;
    localhostProfile?: string;
  };
  seLinuxOptions?: {
    level?: string;
    role?: string;
    type?: string;
    user?: string;
  };
}

export interface K8sSecurityContextAnalysis {
  resourceType: K8sResourceType;
  resourceName: string;
  namespace: string;
  podSecurityContext?: K8sSecurityContext;
  containerSecurityContexts: {
    containerName: string;
    securityContext?: K8sSecurityContext;
  }[];
  issues: K8sMisconfiguration[];
  score: number; // 0-100
  recommendations: string[];
}

export interface K8sRbacRule {
  apiGroups: string[];
  resources: string[];
  verbs: string[];
  resourceNames?: string[];
}

export interface K8sRbacBinding {
  kind: "RoleBinding" | "ClusterRoleBinding";
  name: string;
  namespace?: string;
  roleRef: {
    kind: "Role" | "ClusterRole";
    name: string;
  };
  subjects: {
    kind: "User" | "Group" | "ServiceAccount";
    name: string;
    namespace?: string;
  }[];
}

export interface K8sRbacAuditResult {
  clusterRoles: {
    name: string;
    rules: K8sRbacRule[];
    isClusterAdmin: boolean;
    isHighPrivilege: boolean;
    issues: string[];
  }[];
  roles: {
    name: string;
    namespace: string;
    rules: K8sRbacRule[];
    isHighPrivilege: boolean;
    issues: string[];
  }[];
  bindings: K8sRbacBinding[];
  serviceAccounts: {
    name: string;
    namespace: string;
    roles: string[];
    clusterRoles: string[];
    isHighPrivilege: boolean;
  }[];
  summary: {
    totalClusterRoles: number;
    totalRoles: number;
    totalBindings: number;
    highPrivilegeCount: number;
    clusterAdminBindings: number;
    issues: string[];
  };
}

export interface K8sNetworkPolicy {
  name: string;
  namespace: string;
  podSelector: Record<string, string>;
  policyTypes: ("Ingress" | "Egress")[];
  ingress?: {
    from?: {
      podSelector?: Record<string, string>;
      namespaceSelector?: Record<string, string>;
      ipBlock?: { cidr: string; except?: string[] };
    }[];
    ports?: { protocol?: string; port?: number | string }[];
  }[];
  egress?: {
    to?: {
      podSelector?: Record<string, string>;
      namespaceSelector?: Record<string, string>;
      ipBlock?: { cidr: string; except?: string[] };
    }[];
    ports?: { protocol?: string; port?: number | string }[];
  }[];
}

export interface K8sNetworkPolicyAnalysis {
  namespace: string;
  policies: K8sNetworkPolicy[];
  coverage: {
    podsWithIngress: number;
    podsWithEgress: number;
    podsWithoutPolicy: number;
    totalPods: number;
    coveragePercent: number;
  };
  issues: K8sMisconfiguration[];
  recommendations: string[];
}

export interface K8sClusterScanResult {
  scanId: string;
  clusterName: string;
  scanDate: string;
  kubernetesVersion: string;
  nodeCount: number;
  namespaces: string[];
  misconfigurations: K8sMisconfiguration[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  byCategory: Record<K8sMisconfigCategory, number>;
  byNamespace: Record<string, number>;
  score: number; // 0-100, higher is better
}

export interface K8sNamespaceScanResult {
  scanId: string;
  namespace: string;
  scanDate: string;
  resourceCounts: Record<K8sResourceType, number>;
  misconfigurations: K8sMisconfiguration[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  score: number;
}

export interface K8sScanOptions {
  kubeconfig?: string;
  context?: string;
  namespace?: string;
  excludeNamespaces?: string[];
  severity?: K8sSeverity[];
  categories?: K8sMisconfigCategory[];
  skipTrivyIntegration?: boolean;
}

// =============================================================================
// Utility Functions
// =============================================================================

async function execKubectl(
  args: string[],
  options?: { kubeconfig?: string; context?: string }
): Promise<string> {
  const kubectlArgs = [...args];

  if (options?.kubeconfig) {
    kubectlArgs.unshift(`--kubeconfig=${options.kubeconfig}`);
  }
  if (options?.context) {
    kubectlArgs.unshift(`--context=${options.context}`);
  }

  try {
    const { stdout } = await execFileAsync("kubectl", kubectlArgs, {
      timeout: 60000,
      maxBuffer: 10 * 1024 * 1024,
    });
    return stdout;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`kubectl command failed: ${message}`);
  }
}

function parseJsonOutput<T>(output: string): T {
  try {
    return JSON.parse(output) as T;
  } catch {
    throw new Error("Failed to parse kubectl JSON output");
  }
}

function isPrivilegedVerb(verb: string): boolean {
  const privilegedVerbs = ["*", "create", "delete", "deletecollection", "patch", "update"];
  return privilegedVerbs.includes(verb);
}

function isHighPrivilegeResource(resource: string): boolean {
  const highPrivResources = [
    "*",
    "secrets",
    "pods/exec",
    "pods/attach",
    "serviceaccounts/token",
    "nodes",
    "persistentvolumes",
    "clusterroles",
    "clusterrolebindings",
  ];
  return highPrivResources.includes(resource);
}

// =============================================================================
// Security Context Analysis
// =============================================================================

function analyzeSecurityContext(
  context: K8sSecurityContext | undefined,
  containerName: string
): K8sMisconfiguration[] {
  const issues: K8sMisconfiguration[] = [];

  if (!context) {
    issues.push({
      id: randomUUID(),
      title: "No security context defined",
      description: `Container ${containerName} has no security context configured`,
      severity: "MEDIUM",
      category: "security_context",
      resourceType: "Pod",
      resourceName: "",
      namespace: "",
      remediation: "Define a security context with appropriate restrictions for the container",
      references: ["https://kubernetes.io/docs/tasks/configure-pod-container/security-context/"],
    });
    return issues;
  }

  if (context.privileged === true) {
    issues.push({
      id: randomUUID(),
      title: "Container runs in privileged mode",
      description: `Container ${containerName} is running in privileged mode, giving it full host access`,
      severity: "CRITICAL",
      category: "security_context",
      resourceType: "Pod",
      resourceName: "",
      namespace: "",
      remediation: "Remove privileged: true unless absolutely necessary",
      references: ["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
    });
  }

  if (context.allowPrivilegeEscalation !== false) {
    issues.push({
      id: randomUUID(),
      title: "Privilege escalation not explicitly disabled",
      description: `Container ${containerName} allows privilege escalation`,
      severity: "HIGH",
      category: "security_context",
      resourceType: "Pod",
      resourceName: "",
      namespace: "",
      remediation: "Set allowPrivilegeEscalation: false",
      references: ["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
    });
  }

  if (context.runAsNonRoot !== true && context.runAsUser === undefined) {
    issues.push({
      id: randomUUID(),
      title: "Container may run as root",
      description: `Container ${containerName} does not enforce non-root execution`,
      severity: "HIGH",
      category: "security_context",
      resourceType: "Pod",
      resourceName: "",
      namespace: "",
      remediation: "Set runAsNonRoot: true or specify a non-zero runAsUser",
      references: ["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
    });
  }

  if (context.runAsUser === 0) {
    issues.push({
      id: randomUUID(),
      title: "Container explicitly runs as root",
      description: `Container ${containerName} is configured to run as root (UID 0)`,
      severity: "HIGH",
      category: "security_context",
      resourceType: "Pod",
      resourceName: "",
      namespace: "",
      remediation: "Change runAsUser to a non-zero UID",
      references: ["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
    });
  }

  if (context.readOnlyRootFilesystem !== true) {
    issues.push({
      id: randomUUID(),
      title: "Root filesystem is writable",
      description: `Container ${containerName} has a writable root filesystem`,
      severity: "MEDIUM",
      category: "security_context",
      resourceType: "Pod",
      resourceName: "",
      namespace: "",
      remediation: "Set readOnlyRootFilesystem: true and use emptyDir volumes for writable paths",
      references: ["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
    });
  }

  // Check for dangerous capabilities
  const dangerousCaps = [
    "SYS_ADMIN",
    "NET_ADMIN",
    "SYS_PTRACE",
    "SYS_MODULE",
    "DAC_OVERRIDE",
    "NET_RAW",
  ];
  if (context.capabilities?.add) {
    for (const cap of context.capabilities.add) {
      if (dangerousCaps.includes(cap)) {
        issues.push({
          id: randomUUID(),
          title: `Dangerous capability added: ${cap}`,
          description: `Container ${containerName} adds the ${cap} capability which could be exploited`,
          severity: cap === "SYS_ADMIN" ? "CRITICAL" : "HIGH",
          category: "security_context",
          resourceType: "Pod",
          resourceName: "",
          namespace: "",
          remediation: `Remove the ${cap} capability unless absolutely required`,
          references: [
            "https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container",
          ],
        });
      }
    }
  }

  // Check if ALL capabilities are dropped
  if (!context.capabilities?.drop || !context.capabilities.drop.includes("ALL")) {
    issues.push({
      id: randomUUID(),
      title: "Not all capabilities are dropped",
      description: `Container ${containerName} does not drop all capabilities`,
      severity: "MEDIUM",
      category: "security_context",
      resourceType: "Pod",
      resourceName: "",
      namespace: "",
      remediation: 'Add capabilities.drop: ["ALL"] and only add back required capabilities',
      references: ["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
    });
  }

  return issues;
}

// =============================================================================
// RBAC Analysis
// =============================================================================

function analyzeRbacRule(rule: K8sRbacRule): {
  isHighPrivilege: boolean;
  issues: string[];
} {
  const issues: string[] = [];
  let isHighPrivilege = false;

  // Check for wildcard access
  if (rule.apiGroups.includes("*")) {
    issues.push("Wildcard API group access");
    isHighPrivilege = true;
  }

  if (rule.resources.includes("*")) {
    issues.push("Wildcard resource access");
    isHighPrivilege = true;
  }

  if (rule.verbs.includes("*")) {
    issues.push("Wildcard verb access (full control)");
    isHighPrivilege = true;
  }

  // Check for high-privilege resources
  for (const resource of rule.resources) {
    if (isHighPrivilegeResource(resource)) {
      issues.push(`High-privilege resource access: ${resource}`);
      isHighPrivilege = true;
    }
  }

  // Check for dangerous verbs on sensitive resources
  for (const verb of rule.verbs) {
    if (isPrivilegedVerb(verb)) {
      for (const resource of rule.resources) {
        if (["secrets", "pods/exec", "pods/attach"].includes(resource)) {
          issues.push(`${verb} access to ${resource}`);
          isHighPrivilege = true;
        }
      }
    }
  }

  return { isHighPrivilege, issues };
}

// =============================================================================
// Core Functions
// =============================================================================

/**
 * Check if kubectl is available and configured
 */
export async function isKubectlAvailable(): Promise<boolean> {
  try {
    await execFileAsync("kubectl", ["version", "--client"], {
      timeout: 10000,
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * Get Kubernetes cluster info
 */
export async function getClusterInfo(options?: { kubeconfig?: string; context?: string }): Promise<{
  version: string;
  nodeCount: number;
  namespaces: string[];
}> {
  const versionOutput = await execKubectl(["version", "-o", "json"], options);
  const versionInfo = parseJsonOutput<{
    serverVersion?: { gitVersion: string };
  }>(versionOutput);

  const nodesOutput = await execKubectl(["get", "nodes", "-o", "json"], options);
  const nodesInfo = parseJsonOutput<{ items: unknown[] }>(nodesOutput);

  const nsOutput = await execKubectl(
    ["get", "namespaces", "-o", "jsonpath={.items[*].metadata.name}"],
    options
  );
  const namespaces = nsOutput.trim().split(/\s+/).filter(Boolean);

  return {
    version: versionInfo.serverVersion?.gitVersion || "unknown",
    nodeCount: nodesInfo.items.length,
    namespaces,
  };
}

/**
 * Scan a Kubernetes cluster for security misconfigurations
 */
export async function scanK8sCluster(options?: K8sScanOptions): Promise<K8sClusterScanResult> {
  const kubectlOpts = {
    kubeconfig: options?.kubeconfig,
    context: options?.context,
  };

  // Get cluster info
  const clusterInfo = await getClusterInfo(kubectlOpts);

  // Filter namespaces
  let namespaces = clusterInfo.namespaces;
  const excludeNs = options?.excludeNamespaces || ["kube-system", "kube-public", "kube-node-lease"];
  if (!options?.namespace) {
    namespaces = namespaces.filter((ns) => !excludeNs.includes(ns));
  } else {
    namespaces = [options.namespace];
  }

  const misconfigurations: K8sMisconfiguration[] = [];

  // Scan each namespace
  for (const ns of namespaces) {
    const nsResult = await scanK8sNamespace(ns, options);
    misconfigurations.push(...nsResult.misconfigurations);
  }

  // Filter by severity if specified
  let filteredMisconfigs = misconfigurations;
  if (options?.severity && options.severity.length > 0) {
    filteredMisconfigs = misconfigurations.filter((m) => options.severity!.includes(m.severity));
  }

  // Filter by category if specified
  if (options?.categories && options.categories.length > 0) {
    filteredMisconfigs = filteredMisconfigs.filter((m) => options.categories!.includes(m.category));
  }

  // Calculate summary
  const summary = {
    critical: filteredMisconfigs.filter((m) => m.severity === "CRITICAL").length,
    high: filteredMisconfigs.filter((m) => m.severity === "HIGH").length,
    medium: filteredMisconfigs.filter((m) => m.severity === "MEDIUM").length,
    low: filteredMisconfigs.filter((m) => m.severity === "LOW").length,
    info: filteredMisconfigs.filter((m) => m.severity === "INFO").length,
    total: filteredMisconfigs.length,
  };

  // Count by category
  const byCategory: Record<K8sMisconfigCategory, number> = {
    security_context: 0,
    resource_limits: 0,
    network: 0,
    rbac: 0,
    secrets: 0,
    image: 0,
    pod_security: 0,
    compliance: 0,
  };
  for (const m of filteredMisconfigs) {
    byCategory[m.category]++;
  }

  // Count by namespace
  const byNamespace: Record<string, number> = {};
  for (const m of filteredMisconfigs) {
    byNamespace[m.namespace] = (byNamespace[m.namespace] || 0) + 1;
  }

  // Calculate score (0-100, higher is better)
  const maxScore = 100;
  const penaltyPerCritical = 20;
  const penaltyPerHigh = 10;
  const penaltyPerMedium = 5;
  const penaltyPerLow = 2;

  const totalPenalty =
    summary.critical * penaltyPerCritical +
    summary.high * penaltyPerHigh +
    summary.medium * penaltyPerMedium +
    summary.low * penaltyPerLow;

  const score = Math.max(0, maxScore - totalPenalty);

  return {
    scanId: randomUUID(),
    clusterName: options?.context || "default",
    scanDate: new Date().toISOString(),
    kubernetesVersion: clusterInfo.version,
    nodeCount: clusterInfo.nodeCount,
    namespaces,
    misconfigurations: filteredMisconfigs,
    summary,
    byCategory,
    byNamespace,
    score,
  };
}

/**
 * Scan a specific Kubernetes namespace
 */
export async function scanK8sNamespace(
  namespace: string,
  options?: K8sScanOptions
): Promise<K8sNamespaceScanResult> {
  const kubectlOpts = {
    kubeconfig: options?.kubeconfig,
    context: options?.context,
  };

  const misconfigurations: K8sMisconfiguration[] = [];
  const resourceCounts: Partial<Record<K8sResourceType, number>> = {};

  // Get pods and analyze their security contexts
  try {
    const podsOutput = await execKubectl(
      ["get", "pods", "-n", namespace, "-o", "json"],
      kubectlOpts
    );
    const pods = parseJsonOutput<{
      items: Array<{
        metadata: { name: string; namespace: string };
        spec: {
          securityContext?: K8sSecurityContext;
          containers: Array<{
            name: string;
            securityContext?: K8sSecurityContext;
            resources?: { limits?: Record<string, string>; requests?: Record<string, string> };
            image?: string;
          }>;
        };
      }>;
    }>(podsOutput);
    resourceCounts.Pod = pods.items.length;

    for (const pod of pods.items) {
      // Analyze pod security context
      const podSecCtx = pod.spec.securityContext;

      for (const container of pod.spec.containers || []) {
        const issues = analyzeSecurityContext(
          container.securityContext || podSecCtx,
          container.name
        );

        for (const issue of issues) {
          issue.resourceName = pod.metadata.name;
          issue.namespace = pod.metadata.namespace;
          misconfigurations.push(issue);
        }

        // Check for resource limits
        if (!container.resources?.limits) {
          misconfigurations.push({
            id: randomUUID(),
            title: "No resource limits defined",
            description: `Container ${container.name} in pod ${pod.metadata.name} has no resource limits`,
            severity: "MEDIUM",
            category: "resource_limits",
            resourceType: "Pod",
            resourceName: pod.metadata.name,
            namespace: pod.metadata.namespace,
            remediation: "Define CPU and memory limits for the container",
            references: [
              "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/",
            ],
          });
        }

        // Check for latest tag
        if (container.image?.includes(":latest") || !container.image?.includes(":")) {
          misconfigurations.push({
            id: randomUUID(),
            title: "Using latest or no tag for container image",
            description: `Container ${container.name} uses image ${container.image} with latest or no tag`,
            severity: "MEDIUM",
            category: "image",
            resourceType: "Pod",
            resourceName: pod.metadata.name,
            namespace: pod.metadata.namespace,
            remediation: "Use specific image tags or digests for reproducibility",
            references: ["https://kubernetes.io/docs/concepts/containers/images/"],
          });
        }
      }
    }
  } catch {
    // Namespace might not have pods
  }

  // Get Deployments
  try {
    const deplOutput = await execKubectl(
      ["get", "deployments", "-n", namespace, "-o", "json"],
      kubectlOpts
    );
    const deployments = parseJsonOutput<{ items: unknown[] }>(deplOutput);
    resourceCounts.Deployment = deployments.items.length;
  } catch {
    resourceCounts.Deployment = 0;
  }

  // Get Services
  try {
    const svcOutput = await execKubectl(
      ["get", "services", "-n", namespace, "-o", "json"],
      kubectlOpts
    );
    const services = parseJsonOutput<{ items: unknown[] }>(svcOutput);
    resourceCounts.Service = services.items.length;
  } catch {
    resourceCounts.Service = 0;
  }

  // Get Secrets and check for issues
  try {
    const secretsOutput = await execKubectl(
      ["get", "secrets", "-n", namespace, "-o", "json"],
      kubectlOpts
    );
    const secrets = parseJsonOutput<{
      items: Array<{
        metadata: { name: string; namespace: string };
        type: string;
      }>;
    }>(secretsOutput);
    resourceCounts.Secret = secrets.items.length;
  } catch {
    resourceCounts.Secret = 0;
  }

  // Get NetworkPolicies
  try {
    const npOutput = await execKubectl(
      ["get", "networkpolicies", "-n", namespace, "-o", "json"],
      kubectlOpts
    );
    const policies = parseJsonOutput<{ items: unknown[] }>(npOutput);
    resourceCounts.NetworkPolicy = policies.items.length;

    // Check if namespace has no network policies
    if (policies.items.length === 0 && (resourceCounts.Pod || 0) > 0) {
      misconfigurations.push({
        id: randomUUID(),
        title: "No network policies in namespace",
        description: `Namespace ${namespace} has pods but no network policies`,
        severity: "MEDIUM",
        category: "network",
        resourceType: "NetworkPolicy",
        resourceName: "",
        namespace: namespace,
        remediation: "Create network policies to restrict pod-to-pod communication",
        references: ["https://kubernetes.io/docs/concepts/services-networking/network-policies/"],
      });
    }
  } catch {
    resourceCounts.NetworkPolicy = 0;
  }

  // Calculate summary
  const summary = {
    critical: misconfigurations.filter((m) => m.severity === "CRITICAL").length,
    high: misconfigurations.filter((m) => m.severity === "HIGH").length,
    medium: misconfigurations.filter((m) => m.severity === "MEDIUM").length,
    low: misconfigurations.filter((m) => m.severity === "LOW").length,
    info: misconfigurations.filter((m) => m.severity === "INFO").length,
    total: misconfigurations.length,
  };

  // Calculate score
  const maxScore = 100;
  const penalty = summary.critical * 20 + summary.high * 10 + summary.medium * 5 + summary.low * 2;
  const score = Math.max(0, maxScore - penalty);

  return {
    scanId: randomUUID(),
    namespace,
    scanDate: new Date().toISOString(),
    resourceCounts: resourceCounts as Record<K8sResourceType, number>,
    misconfigurations,
    summary,
    score,
  };
}

/**
 * Get and analyze security contexts for workloads in a namespace
 */
export async function getSecurityContexts(
  namespace: string,
  options?: { kubeconfig?: string; context?: string }
): Promise<K8sSecurityContextAnalysis[]> {
  const kubectlOpts = options || {};
  const results: K8sSecurityContextAnalysis[] = [];

  // Get pods
  const podsOutput = await execKubectl(["get", "pods", "-n", namespace, "-o", "json"], kubectlOpts);
  const pods = parseJsonOutput<{
    items: Array<{
      metadata: { name: string; namespace: string };
      spec: {
        securityContext?: K8sSecurityContext;
        containers: Array<{
          name: string;
          securityContext?: K8sSecurityContext;
        }>;
      };
    }>;
  }>(podsOutput);

  for (const pod of pods.items) {
    const containerContexts = pod.spec.containers.map((c) => ({
      containerName: c.name,
      securityContext: c.securityContext,
    }));

    const allIssues: K8sMisconfiguration[] = [];
    const recommendations: string[] = [];

    // Analyze pod-level security context
    if (!pod.spec.securityContext) {
      recommendations.push("Define a pod-level security context");
    }

    // Analyze each container
    for (const container of pod.spec.containers) {
      const issues = analyzeSecurityContext(
        container.securityContext || pod.spec.securityContext,
        container.name
      );
      for (const issue of issues) {
        issue.resourceName = pod.metadata.name;
        issue.namespace = pod.metadata.namespace;
        allIssues.push(issue);
      }
    }

    // Generate recommendations based on issues
    if (allIssues.some((i) => i.title.includes("privileged"))) {
      recommendations.push("Remove privileged mode from containers");
    }
    if (allIssues.some((i) => i.title.includes("root"))) {
      recommendations.push("Configure containers to run as non-root user");
    }
    if (allIssues.some((i) => i.title.includes("capability"))) {
      recommendations.push("Drop all capabilities and add only required ones");
    }

    // Calculate score
    const score = Math.max(
      0,
      100 -
        allIssues.filter((i) => i.severity === "CRITICAL").length * 25 -
        allIssues.filter((i) => i.severity === "HIGH").length * 15 -
        allIssues.filter((i) => i.severity === "MEDIUM").length * 10 -
        allIssues.filter((i) => i.severity === "LOW").length * 5
    );

    results.push({
      resourceType: "Pod",
      resourceName: pod.metadata.name,
      namespace: pod.metadata.namespace,
      podSecurityContext: pod.spec.securityContext,
      containerSecurityContexts: containerContexts,
      issues: allIssues,
      score,
      recommendations,
    });
  }

  return results;
}

/**
 * Audit RBAC configuration in the cluster
 */
export async function auditRbac(options?: {
  kubeconfig?: string;
  context?: string;
  namespace?: string;
}): Promise<K8sRbacAuditResult> {
  const kubectlOpts = {
    kubeconfig: options?.kubeconfig,
    context: options?.context,
  };

  const result: K8sRbacAuditResult = {
    clusterRoles: [],
    roles: [],
    bindings: [],
    serviceAccounts: [],
    summary: {
      totalClusterRoles: 0,
      totalRoles: 0,
      totalBindings: 0,
      highPrivilegeCount: 0,
      clusterAdminBindings: 0,
      issues: [],
    },
  };

  // Get ClusterRoles
  try {
    const crOutput = await execKubectl(["get", "clusterroles", "-o", "json"], kubectlOpts);
    const clusterRoles = parseJsonOutput<{
      items: Array<{
        metadata: { name: string };
        rules?: K8sRbacRule[];
      }>;
    }>(crOutput);

    for (const cr of clusterRoles.items) {
      const rules = cr.rules || [];
      let isClusterAdmin = false;
      let isHighPrivilege = false;
      const roleIssues: string[] = [];

      for (const rule of rules) {
        const analysis = analyzeRbacRule(rule);
        if (analysis.isHighPrivilege) {
          isHighPrivilege = true;
          roleIssues.push(...analysis.issues);
        }

        // Check for cluster-admin equivalent
        if (
          rule.apiGroups.includes("*") &&
          rule.resources.includes("*") &&
          rule.verbs.includes("*")
        ) {
          isClusterAdmin = true;
        }
      }

      result.clusterRoles.push({
        name: cr.metadata.name,
        rules,
        isClusterAdmin,
        isHighPrivilege,
        issues: roleIssues,
      });

      if (isHighPrivilege) {
        result.summary.highPrivilegeCount++;
      }
    }
    result.summary.totalClusterRoles = clusterRoles.items.length;
  } catch {
    // Failed to get cluster roles
  }

  // Get Roles (namespace-scoped)
  const nsArg = options?.namespace ? ["-n", options.namespace] : ["-A"];
  try {
    const rolesOutput = await execKubectl(["get", "roles", ...nsArg, "-o", "json"], kubectlOpts);
    const roles = parseJsonOutput<{
      items: Array<{
        metadata: { name: string; namespace: string };
        rules?: K8sRbacRule[];
      }>;
    }>(rolesOutput);

    for (const role of roles.items) {
      const rules = role.rules || [];
      let isHighPrivilege = false;
      const roleIssues: string[] = [];

      for (const rule of rules) {
        const analysis = analyzeRbacRule(rule);
        if (analysis.isHighPrivilege) {
          isHighPrivilege = true;
          roleIssues.push(...analysis.issues);
        }
      }

      result.roles.push({
        name: role.metadata.name,
        namespace: role.metadata.namespace,
        rules,
        isHighPrivilege,
        issues: roleIssues,
      });
    }
    result.summary.totalRoles = roles.items.length;
  } catch {
    // Failed to get roles
  }

  // Get ClusterRoleBindings
  try {
    const crbOutput = await execKubectl(["get", "clusterrolebindings", "-o", "json"], kubectlOpts);
    const bindings = parseJsonOutput<{
      items: Array<{
        metadata: { name: string };
        roleRef: { kind: string; name: string };
        subjects?: Array<{ kind: string; name: string; namespace?: string }>;
      }>;
    }>(crbOutput);

    for (const binding of bindings.items) {
      const subjects = (binding.subjects || []).map((s) => ({
        kind: s.kind as "User" | "Group" | "ServiceAccount",
        name: s.name,
        namespace: s.namespace,
      }));

      result.bindings.push({
        kind: "ClusterRoleBinding",
        name: binding.metadata.name,
        roleRef: {
          kind: binding.roleRef.kind as "Role" | "ClusterRole",
          name: binding.roleRef.name,
        },
        subjects,
      });

      // Check for cluster-admin bindings
      if (binding.roleRef.name === "cluster-admin") {
        result.summary.clusterAdminBindings++;
        result.summary.issues.push(
          `ClusterRoleBinding ${binding.metadata.name} grants cluster-admin access`
        );
      }
    }
  } catch {
    // Failed to get cluster role bindings
  }

  // Get RoleBindings
  try {
    const rbOutput = await execKubectl(
      ["get", "rolebindings", ...nsArg, "-o", "json"],
      kubectlOpts
    );
    const bindings = parseJsonOutput<{
      items: Array<{
        metadata: { name: string; namespace: string };
        roleRef: { kind: string; name: string };
        subjects?: Array<{ kind: string; name: string; namespace?: string }>;
      }>;
    }>(rbOutput);

    for (const binding of bindings.items) {
      const subjects = (binding.subjects || []).map((s) => ({
        kind: s.kind as "User" | "Group" | "ServiceAccount",
        name: s.name,
        namespace: s.namespace,
      }));

      result.bindings.push({
        kind: "RoleBinding",
        name: binding.metadata.name,
        namespace: binding.metadata.namespace,
        roleRef: {
          kind: binding.roleRef.kind as "Role" | "ClusterRole",
          name: binding.roleRef.name,
        },
        subjects,
      });
    }
    result.summary.totalBindings = result.bindings.length;
  } catch {
    // Failed to get role bindings
  }

  // Analyze ServiceAccounts
  try {
    const saOutput = await execKubectl(
      ["get", "serviceaccounts", ...nsArg, "-o", "json"],
      kubectlOpts
    );
    const serviceAccounts = parseJsonOutput<{
      items: Array<{
        metadata: { name: string; namespace: string };
      }>;
    }>(saOutput);

    for (const sa of serviceAccounts.items) {
      // Find roles/clusterroles bound to this SA
      const roles: string[] = [];
      const clusterRoles: string[] = [];
      let isHighPrivilege = false;

      for (const binding of result.bindings) {
        const saSubject = binding.subjects.find(
          (s) =>
            s.kind === "ServiceAccount" &&
            s.name === sa.metadata.name &&
            (s.namespace === sa.metadata.namespace || !s.namespace)
        );

        if (saSubject) {
          if (binding.roleRef.kind === "ClusterRole") {
            clusterRoles.push(binding.roleRef.name);
            // Check if it's a high-privilege cluster role
            const cr = result.clusterRoles.find((r) => r.name === binding.roleRef.name);
            if (cr?.isHighPrivilege || cr?.isClusterAdmin) {
              isHighPrivilege = true;
            }
          } else {
            roles.push(binding.roleRef.name);
            // Check if it's a high-privilege role
            const r = result.roles.find(
              (role) =>
                role.name === binding.roleRef.name && role.namespace === sa.metadata.namespace
            );
            if (r?.isHighPrivilege) {
              isHighPrivilege = true;
            }
          }
        }
      }

      result.serviceAccounts.push({
        name: sa.metadata.name,
        namespace: sa.metadata.namespace,
        roles,
        clusterRoles,
        isHighPrivilege,
      });
    }
  } catch {
    // Failed to get service accounts
  }

  return result;
}

/**
 * Analyze network policies in a namespace
 */
export async function analyzeNetworkPolicies(
  namespace: string,
  options?: { kubeconfig?: string; context?: string }
): Promise<K8sNetworkPolicyAnalysis> {
  const kubectlOpts = options || {};

  // Get network policies
  const npOutput = await execKubectl(
    ["get", "networkpolicies", "-n", namespace, "-o", "json"],
    kubectlOpts
  );
  const npData = parseJsonOutput<{
    items: Array<{
      metadata: { name: string; namespace: string };
      spec: {
        podSelector: { matchLabels?: Record<string, string> };
        policyTypes?: string[];
        ingress?: unknown[];
        egress?: unknown[];
      };
    }>;
  }>(npOutput);

  const policies: K8sNetworkPolicy[] = npData.items.map((np) => ({
    name: np.metadata.name,
    namespace: np.metadata.namespace,
    podSelector: np.spec.podSelector.matchLabels || {},
    policyTypes: (np.spec.policyTypes as ("Ingress" | "Egress")[]) || [],
    ingress: np.spec.ingress as K8sNetworkPolicy["ingress"],
    egress: np.spec.egress as K8sNetworkPolicy["egress"],
  }));

  // Get pods to calculate coverage
  const podsOutput = await execKubectl(["get", "pods", "-n", namespace, "-o", "json"], kubectlOpts);
  const podsData = parseJsonOutput<{
    items: Array<{
      metadata: { name: string; labels?: Record<string, string> };
    }>;
  }>(podsOutput);

  const totalPods = podsData.items.length;
  let podsWithIngress = 0;
  let podsWithEgress = 0;
  const coveredPods = new Set<string>();

  // Check which pods are covered by policies
  for (const pod of podsData.items) {
    const podLabels = pod.metadata.labels || {};

    for (const policy of policies) {
      // Check if pod matches policy selector
      const selectorLabels = policy.podSelector;
      const matches = Object.entries(selectorLabels).every(
        ([key, value]) => podLabels[key] === value
      );

      // Empty selector matches all pods
      const isEmptySelector = Object.keys(selectorLabels).length === 0;

      if (matches || isEmptySelector) {
        coveredPods.add(pod.metadata.name);
        if (policy.policyTypes.includes("Ingress")) {
          podsWithIngress++;
        }
        if (policy.policyTypes.includes("Egress")) {
          podsWithEgress++;
        }
      }
    }
  }

  const podsWithoutPolicy = totalPods - coveredPods.size;
  const coveragePercent = totalPods > 0 ? (coveredPods.size / totalPods) * 100 : 100;

  const issues: K8sMisconfiguration[] = [];
  const recommendations: string[] = [];

  // Check for issues
  if (policies.length === 0 && totalPods > 0) {
    issues.push({
      id: randomUUID(),
      title: "No network policies in namespace",
      description: `Namespace ${namespace} has ${totalPods} pods but no network policies`,
      severity: "MEDIUM",
      category: "network",
      resourceType: "NetworkPolicy",
      resourceName: "",
      namespace,
      remediation: "Create default deny policies and allow only required traffic",
      references: ["https://kubernetes.io/docs/concepts/services-networking/network-policies/"],
    });
    recommendations.push("Create a default deny-all ingress policy");
    recommendations.push("Create a default deny-all egress policy");
  }

  if (coveragePercent < 100 && policies.length > 0) {
    issues.push({
      id: randomUUID(),
      title: "Not all pods covered by network policies",
      description: `${podsWithoutPolicy} pods in namespace ${namespace} are not covered by any network policy`,
      severity: "LOW",
      category: "network",
      resourceType: "NetworkPolicy",
      resourceName: "",
      namespace,
      remediation: "Extend network policies to cover all pods",
      references: ["https://kubernetes.io/docs/concepts/services-networking/network-policies/"],
    });
    recommendations.push("Review pods without network policies and add coverage");
  }

  // Check for overly permissive policies
  for (const policy of policies) {
    // Check for allow-all ingress
    if (
      policy.policyTypes.includes("Ingress") &&
      policy.ingress &&
      policy.ingress.some((rule) => !rule.from || rule.from.length === 0)
    ) {
      issues.push({
        id: randomUUID(),
        title: "Overly permissive ingress policy",
        description: `Network policy ${policy.name} allows ingress from all sources`,
        severity: "MEDIUM",
        category: "network",
        resourceType: "NetworkPolicy",
        resourceName: policy.name,
        namespace,
        remediation: "Restrict ingress to specific sources",
        references: ["https://kubernetes.io/docs/concepts/services-networking/network-policies/"],
      });
    }

    // Check for allow-all egress
    if (
      policy.policyTypes.includes("Egress") &&
      policy.egress &&
      policy.egress.some((rule) => !rule.to || rule.to.length === 0)
    ) {
      issues.push({
        id: randomUUID(),
        title: "Overly permissive egress policy",
        description: `Network policy ${policy.name} allows egress to all destinations`,
        severity: "LOW",
        category: "network",
        resourceType: "NetworkPolicy",
        resourceName: policy.name,
        namespace,
        remediation: "Restrict egress to specific destinations",
        references: ["https://kubernetes.io/docs/concepts/services-networking/network-policies/"],
      });
    }
  }

  return {
    namespace,
    policies,
    coverage: {
      podsWithIngress,
      podsWithEgress,
      podsWithoutPolicy,
      totalPods,
      coveragePercent,
    },
    issues,
    recommendations,
  };
}

/**
 * Run Trivy Kubernetes scan (if available)
 */
export async function runTrivyK8sScan(options?: {
  namespace?: string;
  kubeconfig?: string;
  context?: string;
  severity?: string;
}): Promise<{ success: boolean; output?: string; error?: string }> {
  const args = ["k8s", "--report", "summary"];

  if (options?.namespace) {
    args.push("--namespace", options.namespace);
  } else {
    args.push("--all-namespaces");
  }

  if (options?.kubeconfig) {
    args.push("--kubeconfig", options.kubeconfig);
  }

  if (options?.context) {
    args.push("--context", options.context);
  }

  if (options?.severity) {
    args.push("--severity", options.severity);
  }

  args.push("--format", "json");

  return new Promise((resolve) => {
    const trivy = spawn("trivy", args);
    let output = "";
    let error = "";

    trivy.stdout.on("data", (data) => {
      output += data.toString();
    });

    trivy.stderr.on("data", (data) => {
      error += data.toString();
    });

    trivy.on("close", (code) => {
      if (code === 0) {
        resolve({ success: true, output });
      } else {
        resolve({ success: false, error: error || `Trivy exited with code ${code}` });
      }
    });

    trivy.on("error", (err) => {
      resolve({ success: false, error: err.message });
    });
  });
}
