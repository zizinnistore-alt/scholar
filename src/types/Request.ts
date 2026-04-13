// types/request.ts
import { type Request } from "express";

export interface TypedRequest<T> extends Request {
  validatedData: T;
}