import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ResidentApiError } from "@/lib/residentNativeHttp";
import { Route as ForgotPasswordRoute } from "./auth.forgot-password";

const requestPasswordReset = vi.fn();
const verifyPasswordReset = vi.fn();
const completePasswordReset = vi.fn();

vi.mock("@/lib/auth-context", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/auth-context")>();
  return { ...actual, useAuth: () => ({ requestPasswordReset, verifyPasswordReset, completePasswordReset }) };
});

vi.mock("@/components/liveuin/AuthShell", () => ({
  AuthShell: ({ title, children, footer }: { title: string; children: ReactNode; footer?: ReactNode }) => (
    <div>
      <h1>{title}</h1>
      {children}
      {footer}
    </div>
  ),
}));

function renderRoute() {
  const Component = ForgotPasswordRoute.options.component!;
  return render(
    <MemoryRouter>
      <Component />
    </MemoryRouter>,
  );
}

describe("Forgot password", () => {
  beforeEach(() => {
    requestPasswordReset.mockReset();
    verifyPasswordReset.mockReset();
    completePasswordReset.mockReset();
  });

  it("calls the Core password-reset flow: request, verify code, set new password", async () => {
    requestPasswordReset.mockResolvedValue({ resetId: "reset-1", expiresAt: 0 });
    verifyPasswordReset.mockResolvedValue({ resetToken: "token-1" });
    completePasswordReset.mockResolvedValue({});
    renderRoute();

    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "me@example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Send recovery code" }));
    await waitFor(() => expect(requestPasswordReset).toHaveBeenCalledWith("me@example.com"));

    const requested = await screen.findByRole("status");
    expect(requested).toHaveTextContent("Recovery requested.");
    expect(requested).toHaveFocus();
    fireEvent.change(await screen.findByLabelText("Recovery code"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify code" }));
    await waitFor(() => expect(verifyPasswordReset).toHaveBeenCalledWith("reset-1", "123456"));

    fireEvent.change(await screen.findByLabelText("New password"), { target: { value: "a-new-password" } });
    fireEvent.click(screen.getByRole("button", { name: "Save new password" }));
    await waitFor(() => expect(completePasswordReset).toHaveBeenCalledWith("token-1", "a-new-password"));
    expect(await screen.findByText("Password updated")).toBeInTheDocument();
  });

  it("never pretends a reset was sent when Core cannot start recovery, and offers support", async () => {
    requestPasswordReset.mockRejectedValue(new Error("We couldn't start password recovery. Please try again later."));
    renderRoute();

    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "me@example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Send recovery code" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("We couldn't start password recovery");
    expect(screen.queryByText(/Check your inbox/)).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Contact support/ }).getAttribute("href")).toMatch(/^mailto:contact@liveuin\.com/);
  });

  it("reports blank/malformed email instead of silently returning", async () => {
    renderRoute();
    fireEvent.click(screen.getByRole("button", { name: "Send recovery code" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Enter the email");
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "bad-email" } });
    fireEvent.click(screen.getByRole("button", { name: "Send recovery code" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Enter a valid email");
    expect(requestPasswordReset).not.toHaveBeenCalled();
  });

  it("shows an expired-code error and lets the user start a fresh request", async () => {
    requestPasswordReset.mockResolvedValue({ resetId: "reset-1", expiresAt: 0 });
    verifyPasswordReset.mockRejectedValue(new ResidentApiError("That recovery code has expired. Start again.", "json", undefined, undefined, 400, "recovery_expired"));
    renderRoute();
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "me@example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Send recovery code" }));
    await screen.findByLabelText("Recovery code");
    fireEvent.click(screen.getByRole("button", { name: "Verify code" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Enter the recovery code");
    expect(verifyPasswordReset).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText("Recovery code"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify code" }));
    const error = await screen.findByRole("alert");
    await waitFor(() => expect(error).toHaveTextContent("has expired"));
    expect(error).toHaveFocus();
    fireEvent.click(screen.getByRole("button", { name: "Start a new recovery request" }));
    expect(screen.getByLabelText("Email")).toBeInTheDocument();
    expect(screen.queryByLabelText("Recovery code")).not.toBeInTheDocument();
  });

  it("makes a stalled request timeout visible and retryable", async () => {
    let rejectRequest!: (error: Error) => void;
    requestPasswordReset.mockReturnValue(new Promise((_, reject) => { rejectRequest = reject; }));
    renderRoute();
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "me@example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Send recovery code" }));
    expect(screen.getByRole("button", { name: "Sending recovery code…" })).toBeDisabled();
    rejectRequest(new ResidentApiError("LiveUIN took too long to respond. Please try again.", "timeout"));
    expect(await screen.findByRole("alert")).toHaveTextContent("took too long");
    expect(screen.getByRole("button", { name: "Send recovery code" })).toBeEnabled();
    expect(screen.queryByLabelText("Recovery code")).not.toBeInTheDocument();
  });

});
