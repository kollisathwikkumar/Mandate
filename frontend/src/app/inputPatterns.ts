// Keep the hyphen outside a character class so this remains valid under
// the Unicode Sets (v-flag) semantics used by modern HTML pattern validation.
export const RESOURCE_ID_PATTERN = '[A-Za-z0-9](?:[A-Za-z0-9._]|-)*';
