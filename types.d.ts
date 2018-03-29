export interface KeyInterface {
  curve: string
  public: string
  private: string
  id: string
}

export interface SignedObject {
  signature: string
}

export function getTag(string: string): string
export function generate(curve?: string, seed?: Buffer): KeyInterface
export function load(filename: string, cb: (error: Error, keys: KeyInterface) => void): void
export function loadSync(filename: string): KeyInterface
export function create(filename: string, curve: string, legacy: boolean, cb: (error: Error, keys: KeyInterface) => void): void
export function create(filename: string, curve: string, cb: (error: Error, keys: KeyInterface) => void): void
export function create(filename: string, cb: (error: Error, keys: KeyInterface) => void): void
export function createSync(filename: string, curve: string, legacy: boolean): KeyInterface
export function createSync(filename: string): KeyInterface
export function loadOrCreate(filename: string, cb: (err: Error, keys: KeyInterface) => void): void
export function loadOrCreateSync(filename: string): KeyInterface
export function signObj<T = object>(keys: KeyInterface | string, hmac_key: Buffer, obj: T): SignedObject & T
export function signObj<T = object>(keys: KeyInterface | string, obj: T): SignedObject & T
export function verifyObj<T = object>(keys: KeyInterface, hmac_key: Buffer, obj: SignedObject & T): boolean
export function verifyObj<T = object>(keys: KeyInterface, obj: SignedObject & T): boolean
export function box<T = any>(msg: T, recipients: KeyInterface[]): string
export function unbox<T = any>(boxed: string, keys: KeyInterface): T
