/**
 * Build-time constant injected via Vite's define option.
 * This is replaced with the actual encryption key during the build process.
 * 
 * Customers provide their key via:
 *   - npx fpscanner build --key=their-key
 *   - FINGERPRINT_KEY environment variable
 *   - .env file with FINGERPRINT_KEY=their-key
 */
declare const __FP_ENCRYPTION_KEY__: string;
