import type { HardeningRecommendation, RuntimeThreat } from './types.js';
import type { ImageContext } from './runtime-rules.js';

function detectAppType(packages: string[]): 'node' | 'python' | 'java' | 'generic' {
  const pkgStr = packages.join(' ').toLowerCase();
  if (pkgStr.includes('python')) return 'python';
  if (pkgStr.includes('java') || pkgStr.includes('openjdk')) return 'java';
  if (pkgStr.includes('node') || pkgStr.includes('npm')) return 'node';
  return 'generic';
}

function generateSeccompProfile(appType: 'node' | 'python' | 'java' | 'generic'): string {
  const baseProfile = {
    defaultAction: 'SCMP_ACT_ERRNO',
    defaultErrnoRet: 'EPERM',
    archMap: [
      {
        architecture: 'SCMP_ARCH_X86_64',
        subArchitectures: ['SCMP_ARCH_X86', 'SCMP_ARCH_X32'],
      },
    ],
    syscalls: [
      { name: 'arch_prctl', action: 'SCMP_ACT_ALLOW' },
      { name: 'brk', action: 'SCMP_ACT_ALLOW' },
      { name: 'clone', action: 'SCMP_ACT_ALLOW' },
      { name: 'close', action: 'SCMP_ACT_ALLOW' },
      { name: 'exit', action: 'SCMP_ACT_ALLOW' },
      { name: 'exit_group', action: 'SCMP_ACT_ALLOW' },
      { name: 'fcntl', action: 'SCMP_ACT_ALLOW' },
      { name: 'fork', action: 'SCMP_ACT_ALLOW' },
      { name: 'fstat', action: 'SCMP_ACT_ALLOW' },
      { name: 'futex', action: 'SCMP_ACT_ALLOW' },
      { name: 'getcwd', action: 'SCMP_ACT_ALLOW' },
      { name: 'getpid', action: 'SCMP_ACT_ALLOW' },
      { name: 'getrandom', action: 'SCMP_ACT_ALLOW' },
      { name: 'gettimeofday', action: 'SCMP_ACT_ALLOW' },
      { name: 'lseek', action: 'SCMP_ACT_ALLOW' },
      { name: 'madvise', action: 'SCMP_ACT_ALLOW' },
      { name: 'mmap', action: 'SCMP_ACT_ALLOW' },
      { name: 'mprotect', action: 'SCMP_ACT_ALLOW' },
      { name: 'munmap', action: 'SCMP_ACT_ALLOW' },
      { name: 'open', action: 'SCMP_ACT_ALLOW' },
      { name: 'openat', action: 'SCMP_ACT_ALLOW' },
      { name: 'poll', action: 'SCMP_ACT_ALLOW' },
      { name: 'pread64', action: 'SCMP_ACT_ALLOW' },
      { name: 'prlimit64', action: 'SCMP_ACT_ALLOW' },
      { name: 'pwrite64', action: 'SCMP_ACT_ALLOW' },
      { name: 'read', action: 'SCMP_ACT_ALLOW' },
      { name: 'rt_sigaction', action: 'SCMP_ACT_ALLOW' },
      { name: 'rt_sigprocmask', action: 'SCMP_ACT_ALLOW' },
      { name: 'sched_getaffinity', action: 'SCMP_ACT_ALLOW' },
      { name: 'set_tid_address', action: 'SCMP_ACT_ALLOW' },
      { name: 'sigaltstack', action: 'SCMP_ACT_ALLOW' },
      { name: 'socket', action: 'SCMP_ACT_ALLOW' },
      { name: 'stat', action: 'SCMP_ACT_ALLOW' },
      { name: 'statx', action: 'SCMP_ACT_ALLOW' },
      { name: 'write', action: 'SCMP_ACT_ALLOW' },
      { name: 'writev', action: 'SCMP_ACT_ALLOW' },
    ],
  };
  return JSON.stringify(baseProfile, null, 2);
}

function generateAppArmorProfile(appType: 'node' | 'python' | 'java' | 'generic'): string {
  return `#include <tunables/global>

profile container flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  capability,
  network inet,
  network unix,

  # Deny shell access
  deny /bin/sh r,
  deny /bin/bash r,
  deny /usr/bin/sh r,
  deny /usr/bin/bash r,

  owner /proc/*/attr/current r,
  owner /proc/*/status r,

  # Allow application directories
  /app/** rwk,
  /var/lib/** rwk,
  /tmp/** rwk,

  # Deny dangerous system calls
  deny /etc/shadow r,
  deny /etc/gshadow r,
  deny /etc/passwd w,
  deny /root/** rwk,

  # Allow reads of common files
  /etc/hostname r,
  /etc/hosts r,
}`;
}

export function generateHardeningRecommendations(
  context: ImageContext,
  threats: RuntimeThreat[],
): HardeningRecommendation[] {
  const recommendations: HardeningRecommendation[] = [];
  const appType = detectAppType(context.installedPackages);

  // 1. Seccomp profile
  recommendations.push({
    category: 'seccomp',
    title: 'Enable Seccomp Profile',
    description: `Restrict system calls for ${appType} application. Add to docker run: --security-opt seccomp=profile.json`,
    profile: generateSeccompProfile(appType),
    severity: 'HIGH',
  });

  // 2. AppArmor profile
  if (context.hasShell) {
    recommendations.push({
      category: 'apparmor',
      title: 'AppArmor Profile for Shell Denial',
      description: 'Deny shell execution and access to sensitive files',
      profile: generateAppArmorProfile(appType),
      severity: 'HIGH',
    });
  }

  // 3. Non-root user
  if (context.hasRootUser) {
    recommendations.push({
      category: 'user',
      title: 'Run as Non-root User',
      description:
        'Create and use a dedicated non-root user. Add to Dockerfile: RUN useradd -m appuser && USER appuser',
      severity: 'HIGH',
    });
  }

  // 4. Read-only rootfs
  if (context.hasWritableRootfs) {
    recommendations.push({
      category: 'readonly',
      title: 'Enable Read-only Root Filesystem',
      description:
        'Set read-only root filesystem. Add to docker run: --read-only --tmpfs /tmp --tmpfs /var/run',
      severity: 'MEDIUM',
    });
  }

  // 5. Drop capabilities
  recommendations.push({
    category: 'capabilities',
    title: 'Drop Unnecessary Capabilities',
    description:
      'Reduce attack surface by dropping all capabilities. Add to docker run: --cap-drop ALL --cap-add NET_BIND_SERVICE',
    severity: 'MEDIUM',
  });

  return recommendations;
}
