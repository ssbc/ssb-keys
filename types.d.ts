export interface Key {
  curve: Curve
  public: string
  private: string
  id: string
}

export interface SignedObject {
  signature: string
}

type Curve = 'ed25519' | string

type Callback<T> = (error: Error | null, result: T) => void

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
export function signObj<T = Object>(keys: Key | string, hmac_key: Buffer, obj: T): SignedObject & T
export function signObj<T = Object>(keys: Key | string, obj: T): SignedObject & T
export function verifyObj<T = Object>(keys: Key | string, hmac_key: Buffer, obj: SignedObject & T): boolean
export function verifyObj<T = Object>(keys: Key | string, obj: SignedObject & T): boolean
export function box<T = any>(msg: T, recipients: Key[] | string[]): string
export function unbox<T = any>(boxed: string, keys: Key | string): T
