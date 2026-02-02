import { NA } from './utils';

export function cpuCount() {
    return navigator.hardwareConcurrency || NA;
}