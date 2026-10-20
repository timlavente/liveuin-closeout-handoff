#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import postcss from "postcss";

export const manifestPath = "docs/LIVEUIN-RESIDENT-AUTH-FREEZE-20261019.json";

// Dedicated authentication, signed-session, profile authorization and native
// identity sources. Feature routes, menus, homes and generated assets stay open.
export const frozenFiles = [
  "src/main.native.tsx",
  "src/components/liveuin/AuthShell.tsx",
  "src/components/liveuin/AuthFeedback.tsx",
  "src/components/resident/ResidentAppContext.tsx",
  "src/components/resident/ResidentNativeEntryBridge.tsx",
  "src/components/resident/ResidentNativeRouteGate.tsx",
  "src/lib/auth-context.tsx",
  "src/lib/nativeAuthLanding.ts",
  "src/lib/nativeFieldFocus.ts",
  "src/lib/mobileProfileScope.ts",
  "src/lib/profile-context.tsx",
  "src/lib/residentAuthBootstrap.ts",
  "src/lib/residentAuthRedirect.ts",
  "src/lib/residentLogout.ts",
  "src/lib/residentNativeHttp.ts",
  "src/lib/residentNativeLaunch.ts",
  "src/lib/residentPasswordRules.ts",
  "src/lib/residentProfileAuthorization.ts",
  "src/lib/residentSessionBridge.ts",
  "src/lib/residentSessionLifecycle.ts",
  "src/lib/residentSocialAuth.ts",
  "src/lib/residentSocialContinuation.ts",
  "src/lib/runtimeHost.ts",
  "src/native-lovable/components/CompleteProfileForm.tsx",
  "src/native-lovable/routes/auth.cancel-deletion.tsx",
  "src/native-lovable/routes/auth.complete-profile.tsx",
  "src/native-lovable/routes/auth.continue-tenant.tsx",
  "src/native-lovable/routes/auth.forgot-password.tsx",
  "src/native-lovable/routes/auth.sign-in.tsx",
  "src/native-lovable/routes/auth.sign-up.tsx",
  "capacitor.config.json",
  "ios/App/App/AppDelegate.swift",
  "ios/App/App/Info.plist",
  "ios/App/App/App.entitlements",
];

const declarations = {
  "src/NativeApp.tsx": [
    "appQueryClient", "RootRoute", "PublicNativeProviders", "PublicAuthProviders",
    "ProtectedNativeProviders", "SignedAppGate", "NativeProfileGate", "requiredProfileForPath",
    "NativeLovableRoute", "protectedLovableRoutes", "welcomeRoute", "WelcomeComponent",
    "authSignInRoute", "AuthSignInComponent", "publicAuthRoutes",
  ],
  "src/lib/residentAppRuntime.ts": [
    "RESIDENT_AUTH_REQUIRED_EVENT", "isResidentAuthError", "emitResidentAuthRequired",
    "previewAllowed", "errorDetail", "previewBootstrap", "authBootstrap", "asObject", "asList",
    "residentFetchJson", "looksLikeOpaqueIdentityLabel", "safeResidentIdentityLabel", "fetchResidentSessionBootstrap",
  ],
  "src/native-lovable/routeRegistry.tsx": ["nativeLovableRoutes"],
};

const routePaths = [
  "/welcome", "/auth/cancel-deletion", "/auth/complete-profile", "/auth/continue-tenant",
  "/auth/forgot-password", "/auth/sign-in", "/auth/sign-up", "/tenant/home", "/localpro/home",
  "/landlord/home", "/partner/home", "/operator/home", "/family/home",
];

const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const equal = (left, right) => JSON.stringify(left) === JSON.stringify(right);

function sourceFile(file, read) {
  return ts.createSourceFile(file, read(file), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
}

function namedDeclarations(source) {
  const result = new Map();
  for (const node of source.statements) {
    if (ts.isFunctionDeclaration(node) && node.name) result.set(node.name.text, node);
    if (ts.isVariableStatement(node)) {
      for (const declaration of node.declarationList.declarations) {
        if (ts.isIdentifier(declaration.name)) result.set(declaration.name.text, declaration);
      }
    }
  }
  return result;
}

function importHashes(source) {
  return source.statements.filter(ts.isImportDeclaration).map((node) => hash(node.getText(source)));
}

function property(object, name) {
  const matches = object.properties.filter((node) => node.name?.getText().replaceAll('"', "").replaceAll("'", "") === name);
  if (matches.length !== 1 || !ts.isPropertyAssignment(matches[0])) throw new Error(`Expected one property: ${name}`);
  return matches[0].initializer;
}

function walk(node, predicate) {
  const found = [];
  const visit = (child) => {
    if (predicate(child)) found.push(child);
    ts.forEachChild(child, visit);
  };
  visit(node);
  return found;
}

function routeBindings(read) {
  const source = sourceFile("src/native-lovable/routeRegistry.tsx", read);
  const declaration = namedDeclarations(source).get("nativeLovableRouteParity");
  const filter = declaration?.initializer;
  if (!filter || !ts.isCallExpression(filter) || !ts.isPropertyAccessExpression(filter.expression) ||
      filter.expression.name.text !== "filter" || !ts.isArrayLiteralExpression(filter.expression.expression)) throw new Error("Route registry contract missing");
  const array = filter.expression.expression;
  const imports = new Map();
  for (const node of source.statements.filter(ts.isImportDeclaration)) {
    const bindings = node.importClause?.namedBindings;
    if (!bindings || !ts.isNamedImports(bindings)) continue;
    for (const binding of bindings.elements) imports.set(binding.name.text, {
      module: node.moduleSpecifier.text,
      exported: (binding.propertyName || binding.name).text,
    });
  }
  const result = {};
  for (const routePath of routePaths) {
    const matches = array.elements.filter((node) => ts.isObjectLiteralExpression(node) && property(node, "path").text === routePath);
    if (matches.length !== 1) throw new Error(`Expected one accepted route: ${routePath}`);
    const entry = matches[0];
    const component = property(entry, "component").getText(source);
    const imported = imports.get(component.split(".")[0]);
    if (!imported) throw new Error(`Accepted route import missing: ${routePath}`);
    result[routePath] = { component, imported, source: property(entry, "source").text,
      active: property(entry, "active").getText(source), mapping: property(entry, "mapping").text };
  }
  return { bindings: result, filter: hash(filter.arguments.map((argument) => argument.getText(source)).join(",")) };
}

function collectProtectedChildren(children, source) {
  const hashes = [];
  for (const node of children) {
    if (ts.isJsxText(node) && !node.text.trim()) continue;
    // Keep the exact original registration hash, including mapped routes.
    hashes.push(hash(node.getText(source)));
    if (!ts.isJsxElement(node) || node.openingElement.tagName.getText(source) !== "Route") continue;
    const attributes = node.openingElement.attributes.properties;
    // A presentation provider can wrap existing signed-in routes without
    // changing their URL or registration. Do not look through prefixed/index
    // routes, spreads, data-router props, fragments or conditional expressions.
    if (attributes.length !== 1 || !ts.isJsxAttribute(attributes[0]) || attributes[0].name.text !== "element") continue;
    const initializer = attributes[0].initializer;
    if (!initializer || !ts.isJsxExpression(initializer) || !initializer.expression ||
        !ts.isJsxSelfClosingElement(initializer.expression)) continue;
    hashes.push(...collectProtectedChildren(node.children, source));
  }
  return hashes;
}

function nativeRouting(read) {
  const source = sourceFile("src/NativeApp.tsx", read);
  const app = namedDeclarations(source).get("NativeApp");
  if (!app) throw new Error("Native app declaration missing");
  const groups = walk(app, (node) => ts.isJsxElement(node) && node.openingElement.tagName.getText(source) === "Routes");
  if (groups.length !== 1) throw new Error("Expected one native Routes boundary");
  const children = groups[0].children.filter((node) => !ts.isJsxText(node) || node.text.trim());
  const isProtectedGroup = (node) => ts.isJsxElement(node) &&
    node.openingElement.tagName.getText(source) === "Route" &&
    node.openingElement.attributes.properties.some((attribute) => ts.isJsxAttribute(attribute) &&
      attribute.name.text === "element" && attribute.initializer?.getText(source) === "{<ProtectedNativeProviders />}");
  const protectedGroups = [];
  let protectedContainer;
  for (const node of children) {
    if (isProtectedGroup(node)) {
      protectedGroups.push(node);
      protectedContainer = node;
      continue;
    }
    if (!ts.isJsxElement(node) || node.openingElement.tagName.getText(source) !== "Route") continue;
    const attributes = node.openingElement.attributes.properties;
    // This named presentation bridge may supply URL scope before providers
    // mount. It must wrap only the unchanged protected branch: no public/auth
    // children, siblings, prefixes, spreads, data props or alternate elements.
    if (attributes.length !== 1 || !ts.isJsxAttribute(attributes[0]) || attributes[0].name.text !== "element" ||
        attributes[0].initializer?.getText(source) !== "{<NativeFeatureScopeBridge />}") continue;
    const nested = node.children.filter((child) => !ts.isJsxText(child) || child.text.trim());
    if (nested.length !== 1 || !isProtectedGroup(nested[0])) throw new Error("Presentation scope bridge must contain only the protected native branch");
    protectedGroups.push(nested[0]);
    protectedContainer = node;
  }
  if (protectedGroups.length !== 1) throw new Error("Expected one protected native route branch");
  const protectedGroup = protectedGroups[0];
  return {
    // New route maps are allowed only inside the existing signed-in branch.
    publicChildren: children.filter((node) => node !== protectedContainer).map((node) => hash(node.getText(source))),
    protectedOpening: hash(protectedGroup.openingElement.getText(source)),
    protectedChildren: collectProtectedChildren(protectedGroup.children, source),
  };
}

function authCss(read) {
  const result = {};
  postcss.parse(read("src/index.css")).walkRules((rule) => {
    // Freeze the accepted native viewport, keyboard/font and auth layout rules;
    // new feature selectors elsewhere in this stylesheet remain editable.
    if (!rule.selector.includes("data-liveuin-native-app-only") || rule.selector.includes("liveuin-native-welcome")) return;
    const selector = rule.selector.split(",").map((value) => value.trim()).join(",");
    if (result[selector]) throw new Error("Duplicate protected native CSS selector");
    result[selector] = hash(rule.toString());
  });
  if (!Object.keys(result).length) throw new Error("Native auth CSS rules missing");
  return result;
}

export function createSnapshot(read) {
  const sections = {};
  const requiredImports = {};
  for (const [file, names] of Object.entries(declarations)) {
    const source = sourceFile(file, read);
    const found = namedDeclarations(source);
    sections[file] = Object.fromEntries(names.map((name) => {
      const declaration = found.get(name);
      if (!declaration) throw new Error(`Protected declaration missing: ${file} ${name}`);
      return [name, hash(declaration.getText(source))];
    }));
    requiredImports[file] = importHashes(source);
  }
  const registry = routeBindings(read);
  return { files: Object.fromEntries(frozenFiles.map((file) => [file, hash(read(file))])),
    sections, requiredImports, routes: registry.bindings, routeRegistryFilter: registry.filter,
    nativeRouting: nativeRouting(read), css: authCss(read) };
}

export function compareSnapshot(expected, current) {
  const differences = [];
  if (!equal(Object.keys(expected.files), frozenFiles)) differences.push("freeze file inventory changed");
  for (const [file, digest] of Object.entries(expected.files)) if (current.files[file] !== digest) differences.push(`frozen source changed: ${file}`);
  for (const [file, sections] of Object.entries(expected.sections)) {
    for (const [name, digest] of Object.entries(sections)) if (current.sections[file]?.[name] !== digest) differences.push(`auth declaration changed: ${file} ${name}`);
  }
  for (const [file, imports] of Object.entries(expected.requiredImports)) {
    if (!imports.every((digest) => current.requiredImports[file]?.includes(digest))) differences.push(`existing auth import changed: ${file}`);
  }
  for (const [route, binding] of Object.entries(expected.routes)) if (!equal(current.routes[route], binding)) differences.push(`accepted route binding changed: ${route}`);
  if (expected.routeRegistryFilter !== current.routeRegistryFilter) differences.push("route registry filter changed");
  if (!equal(expected.nativeRouting.publicChildren, current.nativeRouting.publicChildren)) differences.push("public route branch changed or unprotected route added");
  if (expected.nativeRouting.protectedOpening !== current.nativeRouting.protectedOpening) differences.push("signed-in route boundary changed");
  if (!expected.nativeRouting.protectedChildren.every((digest) => current.nativeRouting.protectedChildren.includes(digest))) differences.push("existing protected route registration changed");
  for (const [selector, digest] of Object.entries(expected.css)) if (current.css[selector] !== digest) differences.push(`native auth CSS changed: ${selector}`);
  return differences;
}

function main() {
  const args = process.argv.slice(2);
  if (args.length && (args.length !== 2 || args[0] !== "--root")) throw new Error("Usage: check-resident-auth-freeze.mjs [--root fixture-directory]");
  const root = args.length ? path.resolve(args[1]) : path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const read = (file) => fs.readFileSync(path.join(root, file), "utf8");
  const manifest = JSON.parse(read(manifestPath));
  if (manifest.schema !== "liveuin-resident-auth-freeze-v1") throw new Error("Unsupported auth freeze manifest");
  const differences = compareSnapshot(manifest.reference, createSnapshot(read));
  console.log(`AUTH FREEZE: ${differences.length ? "CHANGED" : "PRESERVED"}`);
  console.log(`accepted_source_commit=${manifest.acceptance.sourceCommit}`);
  console.log("scope=source-and-auth-contracts; generated-payload-parity-is-a-separate-build-check");
  differences.forEach((difference) => console.log(`difference=${difference}`));
  if (differences.length) process.exitCode = 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); } catch (error) {
    console.error(`AUTH FREEZE: FAILED — ${error.message}`);
    process.exitCode = 1;
  }
}
