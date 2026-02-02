/* eslint-disable @typescript-eslint/naming-convention */
import {randomUUID} from 'node:crypto';
import express from 'express';
import cors from 'cors';
import {
  AuthConfig,
  CommercetoolsAgentEssentials,
  Configuration,
} from '../modelcontextprotocol';
import {StreamableHTTPServerTransport} from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {isInitializeRequest} from '@modelcontextprotocol/sdk/types.js';
import {IApp, IStreamServerOptions} from '../types/configuration';
import {ClientCredentialsAuth, ExistingTokenAuth as E} from '../types/auth';

export default class CommercetoolsAgentEssentialsStreamable {
  private app: IApp;
  private authConfig: AuthConfig;
  private server: (sessionId?: string) => Promise<CommercetoolsAgentEssentials>;
  private transports: {[sessionId: string]: StreamableHTTPServerTransport} = {};
  private stateless: boolean;
  private configuration: Configuration;

  constructor({
    authConfig,
    configuration,
    stateless = true,
    streamableHttpOptions,
    server,
    app,
  }: IStreamServerOptions) {
    this.server = server!;
    this.authConfig = authConfig!;
    this.configuration = configuration!;
    this.stateless = stateless;

    const port = Number(process.env.PORT) || 8080;

    // initialize express app
    this.app = app ?? express();
    this.app.use(
      cors({
        origin: [
          'http://localhost:6274', // MCP Inspector
          'http://localhost:3000', // Add other origins as needed
          /^http:\/\/localhost:\d+$/, // Allow any localhost port
        ],
        credentials: true,
        exposedHeaders: ['mcp-session-id', 'Mcp-Session-Id', 'authorization'],
        methods: ['GET', 'POST', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'mcp-session-id'],
      })
    );
    this.app.use(express.json());

    // Request logging middleware
    this.app.use(
      (
        req: express.Request,
        res: express.Response,
        next: express.NextFunction
      ) => {
        console.error(
          `[${new Date().toISOString()}] ${req.method} ${req.path}`
        );
        if (req.body && Object.keys(req.body).length > 0) {
          console.error(`  Body:`, JSON.stringify(req.body, null, 2));
        }
        next();
      }
    );

    /**
     * OAuth Discovery - Protected Resource Metadata
     */
    this.app.get('/.well-known/oauth-protected-resource', (req, res) => {
      console.error('[OAuth Discovery] Serving protected resource metadata');
      const baseUrl =
        process.env.MCP_BASE_URL ||
        process.env.OAUTH_BASE_URL ||
        `http://localhost:${port}`;
      const response = {
        resource: `${baseUrl}/mcp`,
        authorization_servers: [`${baseUrl}/oauth`],
        resource_name: 'MCP Commercetools Resource Server',
      };
      console.error(
        '[OAuth Discovery] Response:',
        JSON.stringify(response, null, 2)
      );
      res.status(200).json(response);
    });

    /**
     * OAuth Discovery - Authorization Server Metadata
     */
    this.app.get('/.well-known/oauth-authorization-server', (req, res) => {
      console.error('[OAuth Discovery] Serving authorization server metadata');
      const baseUrl =
        process.env.MCP_BASE_URL ||
        process.env.OAUTH_BASE_URL ||
        `http://localhost:${port}`;
      const response = {
        issuer: `${baseUrl}/oauth`,
        authorization_endpoint: `${baseUrl}/oauth/authorize`,
        token_endpoint: `${baseUrl}/oauth/token`,
        response_types_supported: ['code'],
        grant_types_supported: ['client_credentials', 'authorization_code'],
        token_endpoint_auth_methods_supported: [
          'client_secret_post',
          'client_secret_basic',
        ],
        code_challenge_methods_supported: ['S256'],
      };
      console.error(
        '[OAuth Discovery] Response:',
        JSON.stringify(response, null, 2)
      );
      res.status(200).json(response);
    });

    this.app.use(express.urlencoded({extended: true}));

    /**
     * OAuth Token Endpoint
     * Exchanges client credentials for commercetools access token
     */
    this.app.post('/oauth/token', async (req, res) => {
      console.error('[OAuth Token] Token exchange request received');
      try {
        const {grant_type, client_id, client_secret} = req.body as {
          grant_type?: string;
          client_id?: string;
          client_secret?: string;
        };

        console.error(`[OAuth Token] Grant type: ${grant_type}`);
        console.error(
          `[OAuth Token] Client ID: ${client_id ? `${client_id.substring(0, 8)}...` : 'missing'}`
        );

        // Validate grant type
        if (grant_type !== 'client_credentials') {
          console.error(
            `[OAuth Token] ❌ Unsupported grant type: ${grant_type}`
          );
          return res.status(400).json({
            error: 'unsupported_grant_type',
            error_description:
              'Only client_credentials grant type is supported',
          });
        }

        // Validate credentials
        if (!client_id || !client_secret) {
          console.error('[OAuth Token] ❌ Missing credentials');
          return res.status(400).json({
            error: 'invalid_request',
            error_description: 'Missing client_id or client_secret',
          });
        }

        // Get token from commercetools
        if (this.authConfig.type === 'client_credentials') {
          const config = this.authConfig as ClientCredentialsAuth;

          console.error(
            `[OAuth Token] Requesting token from commercetools: ${config.authUrl}/oauth/token`
          );
          console.error(`[OAuth Token] Project key: ${config.projectKey}`);

          const credentials = Buffer.from(
            `${client_id}:${client_secret}`
          ).toString('base64');

          const response = await fetch(`${config.authUrl}/oauth/token`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
              Authorization: `Basic ${credentials}`,
            },
            body: new URLSearchParams({
              grant_type: 'client_credentials',
              scope: `manage_project:${config.projectKey}`,
            }).toString(),
          });

          if (!response.ok) {
            const errorText = await response.text();
            console.error(
              `[OAuth Token] ❌ Commercetools auth failed: ${response.status} ${response.statusText}`
            );
            console.error(`[OAuth Token] Error details:`, errorText);
            return res.status(response.status).json({
              error: 'invalid_client',
              error_description: `Failed to authenticate with commercetools: ${errorText}`,
            });
          }

          const tokenData = await response.json();
          console.error('[OAuth Token] ✅ Token obtained successfully');
          console.error(
            `[OAuth Token] Token expires in: ${tokenData.expires_in}s`
          );
          return res.json(tokenData);
        }

        console.error(
          '[OAuth Token] ❌ Server not configured for client_credentials'
        );
        return res.status(500).json({
          error: 'server_error',
          error_description: 'Server authentication configuration error',
        });
      } catch (error) {
        console.error(
          '[OAuth Token] ❌ Exception during token exchange:',
          error
        );
        return res.status(500).json({
          error: 'server_error',
          error_description: (error as Error).message,
        });
      }
    });

    /**
     * OAuth Authorization Endpoint (not implemented for M2M flow)
     */
    this.app.get('/oauth/authorize', (req, res) => {
      console.error(
        '[OAuth Authorize] ❌ Authorization endpoint called (not supported)'
      );
      res.status(400).json({
        error: 'unsupported_response_type',
        error_description:
          'Only client_credentials grant is currently supported',
      });
    });

    /**
     * MCP endpoint for handling tool calls
     */
    this.app.post('/mcp', async (req, res) => {
      console.error('[MCP] Request received');
      try {
        let transport: StreamableHTTPServerTransport;
        let serverInstance = await this.getServer();
        const authHeader = req.headers.authorization as string | undefined;
        const token = authHeader?.split(' ')[1] as string;

        if (!token) {
          console.error('[MCP] ❌ Missing Authorization token');
          return res.status(401).json({
            jsonrpc: '2.0',
            error: {
              code: -32604,
              message: 'Unauthorized: Missing Authorization token',
              data: {
                error: 'Unauthorized',
                error_description: 'Bearer token is required',
              },
            },
            id: null,
          });
        }

        /**
         * if token already exists in the config,
         * use it else use header provided token
         */
        this.authConfig = {
          ...this.authConfig,
          // prioritize Authorization header Token
          accessToken: token || (this.authConfig as E)?.accessToken,
        } as E;

        if (stateless) {
          console.error('[MCP] Using stateless mode');
          transport = new StreamableHTTPServerTransport({
            ...streamableHttpOptions,
            sessionIdGenerator: undefined,
          });

          // if stateless then close each transport and server after use
          res.on('close', async () => {
            console.error(
              '[MCP] Connection closed, cleaning up transport and server'
            );
            // close the transport and server
            await transport.close();
            await serverInstance.close();
          });

          // connect server to the transport
          await serverInstance.connect(transport);
        } else {
          const sessionId = req.headers['mcp-session-id'] as string | undefined;
          console.error(
            `[MCP] Using stateful mode, session ID: ${sessionId || 'none'}`
          );

          if (sessionId && this.transports[sessionId]) {
            console.error(`[MCP] Reusing existing session: ${sessionId}`);
            transport = this.transports[sessionId];
          } else if (!sessionId && isInitializeRequest(req.body)) {
            console.error('[MCP] Initializing new session');
            const generator =
              streamableHttpOptions.sessionIdGenerator &&
              typeof streamableHttpOptions.sessionIdGenerator == 'function'
                ? streamableHttpOptions.sessionIdGenerator
                : randomUUID;

            transport = new StreamableHTTPServerTransport({
              sessionIdGenerator: generator,
              onsessioninitialized: async (sessionId) => {
                console.error(`[MCP] ✅ New session initialized: ${sessionId}`);
                // Store the transport by session ID
                this.transports[sessionId] = transport;

                // connect server to the transport
                serverInstance = await this.getServer(sessionId);
                await serverInstance.connect(transport);
              },
            });

            // Clean up transport when closed
            transport.onclose = () => {
              if (transport.sessionId) {
                console.error(`[MCP] Session closed: ${transport.sessionId}`);
                delete this.transports[transport.sessionId];
              }
            };
          } else {
            console.error('[MCP] ❌ Bad request: No valid session ID');
            return res.status(400).json({
              jsonrpc: '2.0',
              error: {
                code: -32000,
                message: 'Bad Request: No valid session ID provided',
              },
              id: null,
            });
          }
        }

        console.error(
          `[MCP] Handling request: ${(req.body as {method?: string})?.method || 'unknown method'}`
        );
        // finally handle requests
        await transport.handleRequest(req, res, req.body);
        console.error('[MCP] ✅ Request handled successfully');
      } catch (err: unknown) {
        // handle error
        console.error('[MCP] ❌ Error handling request:', err);
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: '2.0',
            error: {
              code: -32603,
              message: 'Internal server error',
            },
            id: null,
          });
        }
      }
    });

    /**
     * SSE endpoint (if needed)
     */
    this.app.get('/mcp', (req, res) => {
      console.error('[MCP] /get endpoint called (not implemented)');
      /* noop or implement SSE */
    });
  }

  // eslint-disable-next-line require-await
  private async getServer(id?: string): Promise<CommercetoolsAgentEssentials> {
    if (this.server) return this.server(id);
    return CommercetoolsAgentEssentials.create({
      authConfig: this.authConfig,
      configuration: {
        ...this.configuration,
        context: {
          ...this.configuration.context,
          mode: this.stateless ? 'stateless' : 'stateful',
          sessionId: id,
        },
      },
    });
  }

  listen(port: number, cb?: () => void) {
    const server = this.app.listen(port, cb);
    return server;
  }
}
