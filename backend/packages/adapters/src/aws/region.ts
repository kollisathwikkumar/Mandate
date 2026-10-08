function normalizeRegion(value: string | undefined): string | undefined {
  const normalized = value?.trim();
  return normalized === undefined || normalized === '' ? undefined : normalized;
}

export function resolveAwsRegion(awsRegion: string | undefined, awsDefaultRegion: string | undefined): string | undefined {
  return normalizeRegion(awsRegion) ?? normalizeRegion(awsDefaultRegion);
}
