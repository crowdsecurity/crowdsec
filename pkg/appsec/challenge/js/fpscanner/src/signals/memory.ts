import { NA } from "./utils";

export function memory() {
    return (navigator as any).deviceMemory || NA;
}