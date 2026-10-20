import {
  Link as RouterLink,
  Outlet,
  useLocation,
  useNavigate as useReactRouterNavigate,
  useParams,
  type LinkProps as RouterLinkProps,
} from "react-router-dom";
import type { ComponentType, ReactNode } from "react";
import { scopedFeatureDestination } from "@/native-r6/featureRouteScope";

type NativeLovableRouteOptions = {
  component?: ComponentType;
  head?: () => unknown;
};

type RouteTarget = {
  to: string;
  params?: Record<string, string | number | undefined | null>;
  search?: string | URLSearchParams | Record<string, string | number | boolean | undefined | null>;
  replace?: boolean;
};

function buildPath(to: string, params?: RouteTarget["params"]) {
  let path = to.replace(/\$([A-Za-z0-9_]+)/g, (_, key) => {
    const value = params?.[key];
    return encodeURIComponent(String(value ?? ""));
  });
  path = path.replace(/\/+/g, "/");
  return path.startsWith("/") ? path : `/${path}`;
}

function buildSearch(search?: RouteTarget["search"]) {
  if (!search) return "";
  if (typeof search === "string") return search.startsWith("?") ? search : `?${search}`;
  if (search instanceof URLSearchParams) {
    const value = search.toString();
    return value ? `?${value}` : "";
  }
  const params = new URLSearchParams();
  Object.entries(search).forEach(([key, value]) => {
    if (value === undefined || value === null || value === "") return;
    params.set(key, String(value));
  });
  const value = params.toString();
  return value ? `?${value}` : "";
}

export function createFileRoute(path: string) {
  return (options: NativeLovableRouteOptions) => ({
    options,
    useParams,
    path,
  });
}

type NativeLovableLinkProps = Omit<RouterLinkProps, "to"> & {
  to: string;
  params?: RouteTarget["params"];
  search?: RouteTarget["search"];
  children?: ReactNode;
};

export function Link({ to, params, search, ...props }: NativeLovableLinkProps) {
  const location = useLocation();
  return <RouterLink {...props} to={scopedFeatureDestination(`${buildPath(to, params)}${buildSearch(search)}`, location.pathname, location.search)} />;
}

export function useNavigate() {
  const navigate = useReactRouterNavigate();
  const location = useLocation();
  return (target: string | RouteTarget | number, options?: { replace?: boolean }) => {
    if (typeof target === "number") {
      navigate(target);
      return Promise.resolve();
    }
    if (typeof target === "string") {
      navigate(scopedFeatureDestination(target, location.pathname, location.search), options);
      return Promise.resolve();
    }
    navigate(scopedFeatureDestination(`${buildPath(target.to, target.params)}${buildSearch(target.search)}`, location.pathname, location.search), {
      replace: target.replace ?? options?.replace,
    });
    return Promise.resolve();
  };
}

export { Outlet, useLocation, useParams };
