import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { ApiError, ApiService, TranslatePipe, type Page } from '@attome/base';

/** `mcp_client::McpServerView`. */
export interface McpServer {
  id:                string;
  name:              string;
  url:               string;
  allow_external:    boolean;
  has_credential:    boolean;
  tools_imported_at: string | null;
}

/** `mcp_client::McpToolView`. */
export interface McpTool {
  id:           string;
  name:         string;
  /** The outside server's own words: shown as untrusted text. */
  description:  string | null;
  risk:         'read' | 'reversible' | 'consequential';
  is_enabled:   boolean;
}

export const MCP_TIERS = ['read', 'reversible', 'consequential'] as const;

/**
 * Outside MCP servers (roadmap N13-T1): register a server, import its
 * tools, then review each one — its description is the server's own and
 * untrusted — set its tier and enable it. Agents reach enabled tools through
 * `mcp.tools` and `mcp.call.*`. Logical CSS only.
 */
@Component({
  selector:        'xrm-ai-mcp-servers',
  standalone:      true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:         [TranslatePipe],
  templateUrl:     './mcp-servers.component.html',
  styleUrls:       ['./mcp-servers.component.css'],
})
export class AiMcpServersComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly tiers   = MCP_TIERS;
  readonly servers = signal<McpServer[]>([]);
  readonly tools   = signal<Record<string, McpTool[]>>({});
  readonly error   = signal<string | null>(null);
  readonly busy    = signal(false);
  readonly newName = signal('');
  readonly newUrl  = signal('');
  readonly newToken = signal('');
  readonly newExternal = signal(false);

  ngOnInit(): void { this.load(); }

  load(): void {
    this.api.get<Page<McpServer>>('/api/v1/admin/mcp-servers').subscribe({
      next: page => this.servers.set(page.items ?? []),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  register(): void {
    const name = this.newName().trim();
    const url = this.newUrl().trim();
    if (!name || !url) return;
    this.busy.set(true);
    this.error.set(null);
    const token = this.newToken().trim();
    this.api.post<McpServer>('/api/v1/admin/mcp-servers', {
      name, url, allow_external: this.newExternal(), ...(token ? { credential: token } : {}),
    }).subscribe({
      next: () => {
        this.busy.set(false);
        this.newName.set(''); this.newUrl.set(''); this.newToken.set(''); this.newExternal.set(false);
        this.load();
      },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  loadTools(server: McpServer): void {
    this.api.get<Page<McpTool>>(`/api/v1/admin/mcp-servers/${encodeURIComponent(server.id)}/tools`).subscribe({
      next: page => this.tools.set({ ...this.tools(), [server.id]: page.items ?? [] }),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  importTools(server: McpServer): void {
    this.busy.set(true);
    this.error.set(null);
    this.api.post<Page<McpTool>>(`/api/v1/admin/mcp-servers/${encodeURIComponent(server.id)}/import`, {}).subscribe({
      next: page => {
        this.busy.set(false);
        this.tools.set({ ...this.tools(), [server.id]: page.items ?? [] });
        this.load();
      },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  setTool(server: McpServer, tool: McpTool, risk: string, enabled: boolean): void {
    this.api.put<void>(
      `/api/v1/admin/mcp-servers/${encodeURIComponent(server.id)}/tools/${encodeURIComponent(tool.name)}`,
      { risk, enabled },
    ).subscribe({
      next: () => this.loadTools(server),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }
}
