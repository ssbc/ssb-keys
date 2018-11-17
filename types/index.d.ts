// TypeScript Version: 2.8

export interface Key {
  curve: Curve
  public: string
  private: string
  id: string
}

export interface SignedObject {
  signature: string
}

export type Curve = 'ed25519' | string

export type Callback<T> = (error: Error | null, result: T) => void

export function getTag(string: string): string
export function generate(curve?: Curve, seed?: Buffer): Key
export function load(filename: string, cb: Callback<Key>): void
export function loadSync(filename: string): Key
export function create(filename: string, curve: Curve, legacy: boolean, cb: Callback<Key>): void
export function create(filename: string, curve: Curve, cb: Callback<Key>): void
export function create(filename: string, cb: Callback<Key>): void
export function createSync(filename: string, curve: Curve, legacy: boolean): Key
export function createSync(filename: string): Key
export function loadOrCreate(filename: string, cb: Callback<Key>): void
export function loadOrCreateSync(filename: string): Key
export function signObj<T>(keys: Key | string, hmac_key: Buffer, obj: T): SignedObject & T
export function signObj<T>(keys: Key | string, obj: T): SignedObject & T
export function verifyObj(keys: Key | string, hmac_key: Buffer, obj: SignedObject & any): boolean
export function verifyObj(keys: Key | string, obj: SignedObject & any): boolean
export function box(msg: any, recipients: Key[] | string[]): string
export function unbox(boxed: string, keys: Key | string): any
