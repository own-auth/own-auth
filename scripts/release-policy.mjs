const versionNumber = "(?:0|[1-9]\\d*)";
const stableVersionPattern = new RegExp(
  `^${versionNumber}\\.${versionNumber}\\.${versionNumber}$`
);
const nextVersionPattern = new RegExp(
  `^(${versionNumber}\\.${versionNumber}\\.${versionNumber})-next\\.${versionNumber}$`
);

const channels = {
  stable: {
    distTag: "latest",
    example: "0.3.0"
  },
  next: {
    distTag: "next",
    example: "0.4.0-next.0"
  }
};

export function createReleasePlan(channel, version) {
  const channelConfig = channels[channel];
  if (!channelConfig) {
    throw new Error(`Unknown release channel: ${channel}`);
  }

  const nextMatch = nextVersionPattern.exec(version);
  const valid = channel === "stable"
    ? stableVersionPattern.test(version)
    : nextMatch !== null;

  if (!valid) {
    throw new Error(
      `${channel} releases require a version like ${channelConfig.example}; received ${version}`
    );
  }

  const baseVersion = channel === "stable" ? version : nextMatch[1];

  return {
    baseVersion,
    channel,
    changelogHeading: `## ${baseVersion}`,
    distTag: channelConfig.distTag,
    tagName: `v${version}`,
    version
  };
}

export function inferReleasePlan(version) {
  if (stableVersionPattern.test(version)) {
    return createReleasePlan("stable", version);
  }
  if (nextVersionPattern.test(version)) {
    return createReleasePlan("next", version);
  }
  throw new Error(
    `Unsupported release version ${version}; use x.y.z or x.y.z-next.n`
  );
}

export function validateReleaseFiles({ changelog, packageName, packageVersion, rootVersion }, channel) {
  if (packageName !== "own-auth") {
    throw new Error(`Expected package name own-auth; received ${packageName}`);
  }
  if (rootVersion !== packageVersion) {
    throw new Error(
      `Workspace version ${rootVersion} does not match own-auth version ${packageVersion}`
    );
  }

  const plan = channel
    ? createReleasePlan(channel, packageVersion)
    : inferReleasePlan(packageVersion);
  const headings = new Set(
    changelog.match(/^##\s+[^\r\n]+$/gm)?.map((heading) => heading.trim()) ?? []
  );

  if (!headings.has(plan.changelogHeading)) {
    throw new Error(`CHANGELOG.md is missing ${plan.changelogHeading}`);
  }

  return plan;
}
