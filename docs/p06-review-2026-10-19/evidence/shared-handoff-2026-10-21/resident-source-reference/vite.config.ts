import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react-swc";
import fs from "node:fs/promises";
import path from "path";

const publicWebsiteApiPaths = new Set(["/api", "/api/integrations"]);

function publicWebsiteApiRoutePlugin() {
  const rejectPublicHealthFallback = (
    req: { method?: string; url?: string },
    res: { statusCode: number; setHeader: (name: string, value: string) => void; end: (body?: string) => void },
  ) => {
    const method = String(req.method || "GET").toUpperCase();
    const pathname = String(req.url || "").split("?")[0];
    if ((method === "GET" || method === "HEAD") && pathname === "/api/health") {
      res.statusCode = 404;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.setHeader("Cache-Control", "no-store");
      res.end(method === "HEAD" ? undefined : JSON.stringify({ ok: false, detail: "not_found" }));
      return true;
    }
    return false;
  };

  const rewritePublicApiPage = (req: { method?: string; url?: string }) => {
    const method = String(req.method || "GET").toUpperCase();
    const pathname = String(req.url || "").split("?")[0];
    if ((method === "GET" || method === "HEAD") && publicWebsiteApiPaths.has(pathname)) {
      req.url = "/";
    }
  };

  return {
    name: "liveuin-public-website-api-routes",
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        if (rejectPublicHealthFallback(req, res)) return;
        rewritePublicApiPage(req);
        next();
      });
    },
    configurePreviewServer(server) {
      server.middlewares.use((req, res, next) => {
        if (rejectPublicHealthFallback(req, res)) return;
        rewritePublicApiPage(req);
        next();
      });
    },
  };
}

function nativePrivateAppEntryPlugin(enabled: boolean) {
  const withNativeOnlyHtmlFlag = (html: string) => {
    if (html.includes("data-liveuin-native-app-only")) return html;
    return html.replace("<html", '<html data-liveuin-native-app-only="true"');
  };

  return {
    name: "liveuin-native-private-app-entry",
    transformIndexHtml(html: string) {
      if (!enabled) return html;
      return withNativeOnlyHtmlFlag(html).replace('/src/main.tsx', '/src/main.native.tsx');
    },
    transform(code: string, id: string) {
      if (!enabled || !id.endsWith("/src/main.tsx")) return null;
      return code.replace('import App from "./App.tsx";', 'import App from "./NativeApp.tsx";');
    },
  };
}

function residentWellKnownStaticFilesPlugin() {
  return {
    name: "liveuin-resident-well-known-static-files",
    async closeBundle() {
      const projectRoot = __dirname;
      const sourceDir = path.join(projectRoot, "public", ".well-known");
      const outputDir = path.join(projectRoot, "dist", ".well-known");
      const files = ["apple-app-site-association", "assetlinks.json"];

      await fs.mkdir(outputDir, { recursive: true });
      await Promise.all(
        files.map(async (fileName) => {
          const source = path.join(sourceDir, fileName);
          const target = path.join(outputDir, fileName);
          try {
            await fs.copyFile(source, target);
          } catch (error) {
            if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
              return;
            }
            throw error;
          }
        }),
      );
    },
  };
}

function nativeCustomerFontsPlugin(enabled: boolean) {
  return {
    name: "liveuin-native-customer-fonts",
    async closeBundle() {
      if (!enabled) return;
      // Native builds exclude publicDir. Package only the customer fonts and
      // their license; a missing required file must fail the build.
      const folder = path.join("fonts", "liveuin-r6");
      const targetDir = path.join(__dirname, "dist", folder);
      await fs.mkdir(targetDir, { recursive: true });
      await Promise.all(
        ["archivo-500.ttf", "archivo-600.ttf", "archivo-700.ttf", "archivo-800.ttf", "OFL.txt"].map(
          (fileName) => fs.copyFile(path.join(__dirname, "public", folder, fileName), path.join(targetDir, fileName)),
        ),
      );
    },
  };
}

// https://vitejs.dev/config/
export default defineConfig(async ({ mode }) => {
  const localEnv = loadEnv(mode, process.cwd(), "");
  const nativePrivateAppOnly = process.env.LIVEUIN_NATIVE_APP_ONLY === "1";
  const buildBase = process.env.LIVEUIN_PREVIEW_BASE || "/";
  const plugins = [
    publicWebsiteApiRoutePlugin(),
    nativePrivateAppEntryPlugin(nativePrivateAppOnly),
    residentWellKnownStaticFilesPlugin(),
    nativeCustomerFontsPlugin(nativePrivateAppOnly),
    react(),
  ];
  const allowedHosts = [".liveuin.com", ".laijuzhu.com", "localhost", "127.0.0.1"];
  const localPreviewSafeMode = process.env.LIVEUIN_LOCAL_PREVIEW_SAFE_MODE === "1";
  const localPreviewTraceMode = process.env.LIVEUIN_LOCAL_PREVIEW_TRACE === "1";
  const liveuinViteCacheDir = process.env.LIVEUIN_VITE_CACHE_DIR || "";
  const liveuinPreviewApiPort = process.env.LIVEUIN_PREVIEW_API_PORT || localEnv.LIVEUIN_PREVIEW_API_PORT || "4174";
  const liveuinProgrammeApiPort = process.env.LIVEUIN_PROGRAMME_API_PORT || localEnv.LIVEUIN_PROGRAMME_API_PORT || "4175";

  if (mode === "development") {
    try {
      const { componentTagger } = await import("lovable-tagger");
      plugins.push(componentTagger());
    } catch {
      // Production/liveuin-test builds should not depend on Lovable's editor-only tagger.
    }
  }

  if (localPreviewTraceMode) {
    plugins.push({
      name: "liveuin-local-preview-trace",
      load(id) {
        console.error(`[preview-trace:load] ${id}`);
        return null;
      },
    });
  }

  return {
    base: buildBase,
    publicDir: nativePrivateAppOnly ? false : "public",
    cacheDir: liveuinViteCacheDir || (localPreviewSafeMode ? "/private/tmp/liveuin-vite-cache" : undefined),
    optimizeDeps: localPreviewSafeMode
      ? {
          include: ["react", "react-dom", "react-dom/client", "react/jsx-runtime", "react/jsx-dev-runtime", "react-router-dom", "lucide-react"],
          holdUntilCrawlEnd: false,
        }
      : undefined,
    server: {
      host: "::",
      port: 8080,
      allowedHosts,
      proxy: {
        "/api/core/ai/studio/programme": {
          target: `http://127.0.0.1:${liveuinProgrammeApiPort}`,
          changeOrigin: true,
        },
        "/api/core/identity": {
          target: "http://127.0.0.1:9195",
          changeOrigin: true,
        },
        "/api/core/ops/production-change-requests": {
          target: "http://127.0.0.1:9295",
          changeOrigin: true,
        },
        "/api": {
          target: `http://127.0.0.1:${liveuinPreviewApiPort}`,
          changeOrigin: true,
        },
      },
      hmr: {
        overlay: false,
      },
    },
    preview: {
      host: "::",
      port: 4173,
      allowedHosts,
    },
    build: {
      // Keep Vite's native chunk graph. The former custom vendor partition
      // created a circular ESM initialization between React and vendor code
      // in production preview, leaving the app blank before React mounted.
      rollupOptions: {},
    },
    plugins,
    resolve: {
      alias: {
        ...(localPreviewSafeMode
          ? {
              "@tanstack/react-query": path.resolve(__dirname, "./src/lib/localPreviewReactQuery.tsx"),
              "@/components/ui/sonner": path.resolve(__dirname, "./src/lib/localPreviewSonner.tsx"),
              "@/components/ui/toaster": path.resolve(__dirname, "./src/lib/localPreviewToaster.tsx"),
              "@/components/ui/tooltip": path.resolve(__dirname, "./src/lib/localPreviewTooltip.tsx"),
              "@/components/resident/ResidentNativeEntryBridge": path.resolve(__dirname, "./src/lib/localPreviewResidentNativeEntryBridge.tsx"),
              "@/components/resident/ResidentNativeRouteGate": path.resolve(__dirname, "./src/lib/localPreviewResidentNativeRouteGate.tsx"),
              "@/components/resident/AuthorizedProfileRoute": path.resolve(__dirname, "./src/lib/localPreviewAuthorizedProfileRoute.tsx"),
              "@/components/resident/ResidentRouteAlias": path.resolve(__dirname, "./src/lib/localPreviewResidentRouteAlias.tsx"),
            }
          : {}),
        "@": path.resolve(__dirname, "./src"),
        "get-nonce": path.resolve(__dirname, "./node_modules/get-nonce/dist/es2015/index.js"),
      },
      dedupe: ["react", "react-dom", "react/jsx-runtime", "react/jsx-dev-runtime", "@tanstack/react-query", "@tanstack/query-core"],
    },
  };
});
