import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const GEMINI_KEY = process.env.GEMINI_KEY ?? "";
const GEMINI_MODEL = "gemini-3-pro-image-preview";
const PORT = parseInt(process.env.PORT ?? "8000");

const app = express();
app.use(express.json());

// CORS
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "*");
  res.setHeader("Access-Control-Allow-Headers", "*");
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

// Health
app.get("/ping", (_, res) => res.json({ status: "live", model: GEMINI_MODEL }));
app.get("/", (_, res) => res.json({ status: "NB Pro MCP Server", model: GEMINI_MODEL }));

// MCP endpoint
app.all("/mcp", async (req, res) => {
  const server = new McpServer({
    name: "NB Pro Studio",
    version: "1.0.0",
  });

  server.tool(
    "generate_image",
    "Generate or edit an image using NB Pro (gemini-3-pro-image-preview). Use this whenever the user wants to create or edit any image.",
    {
      prompt: z.string().describe("Detailed image generation or editing prompt"),
      ref_image_b64: z.string().optional().describe("Optional base64 encoded reference image"),
      ref_mime: z.string().optional().default("image/jpeg").describe("MIME type of reference image"),
    },
    async ({ prompt, ref_image_b64, ref_mime }) => {
      const parts: any[] = [];
      if (ref_image_b64) {
        parts.push({ inline_data: { mime_type: ref_mime, data: ref_image_b64 } });
      }
      parts.push({ text: prompt });

      const body = {
        contents: [{ role: "user", parts }],
        generationConfig: { responseModalities: ["TEXT", "IMAGE"] },
      };

      const url = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_KEY}`;
      const r = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      if (!r.ok) {
        const err = await r.text();
        return { content: [{ type: "text", text: `Gemini error: ${err}` }] };
      }

      const data: any = await r.json();
      for (const candidate of data.candidates ?? []) {
        for (const part of candidate.content?.parts ?? []) {
          if (part.inline_data?.mime_type?.startsWith("image/")) {
            return {
              content: [
                {
                  type: "image",
                  data: part.inline_data.data,
                  mimeType: part.inline_data.mime_type,
                },
              ],
            };
          }
        }
      }

      return { content: [{ type: "text", text: "No image returned from Gemini." }] };
    }
  );

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
  });

  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.listen(PORT, () => {
  console.log(`NB Pro MCP Server running on port ${PORT}`);
});
