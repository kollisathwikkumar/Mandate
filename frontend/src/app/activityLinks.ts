export function getActivityDetailHref(subjectType: string, subjectId: string): string | null {
  return subjectType === 'ACTION' ? `/app/activity/${encodeURIComponent(subjectId)}` : null;
}
