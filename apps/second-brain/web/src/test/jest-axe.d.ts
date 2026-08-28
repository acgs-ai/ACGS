declare module "jest-axe" {
  export interface AxeResults {
    violations: unknown[];
  }

  export function axe(container: Element | DocumentFragment): Promise<AxeResults>;
}
