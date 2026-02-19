import { hashCode } from './utils';

export function maths() {
    const results: number[] = [];
    const testValue = 0.123456789;

    // Math constants
    const constants = ["E", "LN10", "LN2", "LOG10E", "LOG2E", "PI", "SQRT1_2", "SQRT2"];
    constants.forEach(function (name) {
        try {
            results.push((Math as any)[name]);
        } catch (e) {
            results.push(-1);
        }
    });

    // Math functions (can reveal VM/browser differences)
    const mathFunctions = ["tan", "sin", "exp", "atan", "acosh", "asinh", "atanh", "expm1", "log1p", "sinh"];


    mathFunctions.forEach(function (name) {
        try {
            results.push((Math as any)[name](testValue));
        } catch (e) {
            results.push(-1);
        }
    });

    return hashCode(results.map(String).join(","));
}