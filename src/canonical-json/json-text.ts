import type { JsonValue } from "./index.js";

export class JsonTextError extends SyntaxError {
  public constructor(message: string) {
    super(message);
    this.name = "JsonTextError";
  }
}

/** Parses JSON text while rejecting repeated decoded object member names. */
export function parseUniqueJsonText(text: string): JsonValue {
  if (typeof text !== "string") {
    throw new JsonTextError("JSON text must be a string");
  }

  let value: JsonValue;
  try {
    value = JSON.parse(text) as JsonValue;
  } catch {
    throw new JsonTextEror("Invalid JSON text");
  }

  let index = 0;
  const skipWhitespace = (): void => {
    while (text[index] === " " || text[index] === "\t" || text[index] === "\n" || text[index] === "\r") {
      index += 1;
    }
  };

  const readString = (): string => {
    const start = index;
    index += 1;
    while (index < text.length) {
      const character = text[index];
      if (character === "\"") {
        index += 1;
        return JSON.parse(text.slice(start, index)) as string;
      }
      if (character === "\\") {
        index += text[index + 1] === "u" ? 6 : 2;
      } else {
        index += 1;
      }
    }
    return "";
  };

  const scanValue = (): void => {
    skipWhitespace();
    if (text[index] === "{") {
      scanObject();
      return;
    }
    if (text[index] === "[") {
      scanArray();
      return;
    }
    if (text[index] === "\"") {
      readString();
      return;
    }
    while (index < text.length && text[index] !== "," && text[index] !== "]" && text[index] !== "}" && text[index] !== " " && text[index] !== "\t" && text[index] !== "\n" && text[index] !== "\r") {
      index += 1;
    }
  };

  const scanObject = (): void => {
    index += 1;
    skipWhitespace();
    if (text[index] === "}") {
      index += 1;
      return;
    }
    const keys = new Set<string>();
    while (true) {
      skipWhitespace();
      const keyPosition = index;
      const key = readString();
      if (keys.has(key)) {
        throw new JsonTextError(`Duplicate JSON object key ${JSON.stringify(key)} at position ${keyPosition}`);
      }
      keys.add(key);
      skipWhitespace();
      index += 1;
      scanValue();
      skipWhitespace();
      if (text[index] === "}") {
        index += 1;
        return;
      }
      index += 1;
    }
  };

  const scanArray = (): void => {
    index += 1;
    skipWhitespace();
    if (text[index] === "]") {
      index += 1;
      return;
    }
    while (true) {
      scanValue();
      skipWhitespace();
      if (text[index] === "]") {
        index += 1;
        return;
      }
      index += 1;
    }
  };

  scanValue();
  return value;
}
