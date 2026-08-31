const CALENDAR_DAY = /^\d{4}-\d{2}-\d{2}$/;

export function inclusiveDateQueryValue(key: string, value: string): string {
  if (!CALENDAR_DAY.test(value)) return value;
  if (key === "date_from") return `${value}T00:00:00.000Z`;
  if (key === "date_to") return `${value}T23:59:59.999Z`;
  return value;
}
