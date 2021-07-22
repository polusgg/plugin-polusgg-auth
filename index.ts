import { UserResponseStructure } from "@polusgg/module-polusgg-auth-api/src/types/userResponseStructure";
import { Requester } from "@polusgg/module-polusgg-auth-api/src/requester/requester";
import { NameServicePriority } from "@polusgg/plugin-polusgg-api/src/services/name";
import { BasePlugin, PluginMetadata } from "@nodepolus/framework/src/api/plugin";
import { MessageReader } from "@nodepolus/framework/src/util/hazelMessage";
import { ServiceType } from "@polusgg/plugin-polusgg-api/src/types/enums";
import { Connection } from "@nodepolus/framework/src/protocol/connection";
import { Services } from "@polusgg/plugin-polusgg-api/src/services";
import { DisconnectReason } from "@nodepolus/framework/src/types";
import { Palette } from "@nodepolus/framework/src/static";
import { Hmac } from "@nodepolus/framework/src/util/hmac";
import { LobbyInstance } from "@nodepolus/framework/src/api/lobby";

const pluginMetadata: PluginMetadata = {
  name: "PolusAuth",
  version: [1, 0, 0],
  authors: [
    {
      name: "Polus.gg",
      email: "contact@polus.gg",
      website: "https://polus.gg",
    },
  ],
  description: "Polus.gg Authentication plugin for NodePolus",
  website: "https://polus.gg",
};

type PolusAuthConfig = {
  token: string;
  enableAuth: boolean;
};

export default class extends BasePlugin {
  private readonly requester: Requester = new Requester("https://account.polus.gg");

  constructor(config: PolusAuthConfig) {
    super(pluginMetadata, {
      enableAuth: true,
    }, config);

    this.server.setInboundPacketTransformer(this.inboundPacketTransformer.bind(this));

    this.requester.setAuthenticationToken(process.env.NP_AUTH_TOKEN ?? config.token);

    const nameService = Services.get(ServiceType.Name);

    this.server.on("player.joined", event => {
      const auth = event.getPlayer().getConnection()?.getMeta<UserResponseStructure>("pgg.auth.self");

      if (auth === undefined) {
        return;
      }

      event.getPlayer().setMeta("pgg.auth.joined", true);

      if (!auth.settings["name.color.gold"] && !auth.settings["name.color.match"]) {
        nameService.setForLobby(event.getPlayer(), auth.display_name, NameServicePriority.High);
      }

      if (auth.settings["name.color.gold"] && !auth.settings["name.color.match"]) {
        nameService.setForLobby(event.getPlayer(), `<color=#DAA520>${auth.display_name}</color>`, NameServicePriority.High);
      }

      if (auth.settings["name.color.match"] && !auth.settings["name.color.gold"]) {
        const body = [...Palette.playerBody()[event.getPlayer().getColor()].light];

        const nameColor = `${body[0].toString(16).padStart(2, "0")}${body[1].toString(16).padStart(2, "0")}${body[2].toString(16).padStart(2, "0")}`;

        nameService.setForLobby(event.getPlayer(), `<color=#${nameColor}>${auth.display_name}</color>`, NameServicePriority.High);
      }
    });

    this.server.on("player.color.updated", async event => {
      const auth = event.getPlayer().getConnection()?.getMeta<UserResponseStructure>("pgg.auth.self");

      if (!event.getPlayer().getMeta<boolean | undefined>("pgg.auth.joined")) {
        return;
      }

      if (auth === undefined) {
        return;
      }

      if (auth.settings["name.color.match"] && !auth.settings["name.color.gold"]) {
        const body = [...Palette.playerBody()[event.getNewColor()].light];

        const nameColor = `${body[0].toString(16).padStart(2, "0")}${body[1].toString(16).padStart(2, "0")}${body[2].toString(16).padStart(2, "0")}`;

        const bodyOld = [...Palette.playerBody()[event.getOldColor()].light];

        const nameColorOld = `${bodyOld[0].toString(16).padStart(2, "0")}${bodyOld[1].toString(16).padStart(2, "0")}${bodyOld[2].toString(16).padStart(2, "0")}`;

        try {
          await nameService.removeForLobby(event.getPlayer(), `<color=#${nameColorOld}>${auth.display_name}</color>`);
        } catch (err) {
          console.log(err);
        }

        nameService.setForLobby(event.getPlayer(), `<color=#${nameColor}>${auth.display_name}</color>`, NameServicePriority.High);
      }
    });

    this.server.on("player.name.updated", event => {
      const auth = event.getPlayer().getConnection()?.getMeta<UserResponseStructure>("pgg.auth.self");

      if (event.getNewName().toString() !== auth?.display_name) {
        event.cancel();
      }
    });

    this.server.on("game.started", event => {
      this.syncGameData(event.getGame().getLobby());
    });

    this.server.on("player.left", event => {
      if (event.getPlayer().getConnection()?.isActingHost()) {
        this.syncGameData(event.getLobby(), event.getPlayer().getConnection() ? [event.getPlayer().getSafeConnection()] : []);
      }
    });
  }

  syncGameData(lobby: LobbyInstance, syncFor: Connection[] = lobby.getActingHosts()): void {
    syncFor.forEach(host => {
      const json = Object.values(Services.get(ServiceType.GameOptions).getGameOptions(lobby).getAllOptions()).map(option => option.toJson());

      this.requester.setUserGameOptions(host.getMeta<UserResponseStructure>("pgg.auth.self").client_id, json);
    });
  }

  //#region Packet Authentication
  inboundPacketTransformer(connection: Connection, packet: MessageReader): MessageReader {
    if (packet.readByte() !== 0x80) {
      this.getLogger().warn("Connection %s attempted to send an unauthenticated packet %s", connection, packet);
      connection.disconnect(DisconnectReason.custom("Authentication Error."));

      return MessageReader.fromRawBytes([0x00]);
    }

    //1 byte for authentication magic (0x80)
    //16 bytes for client UUID
    //20 bytes for SHA1 HMAC
    if (packet.getLength() < 1 + 16 + 20) {
      this.getLogger().warn("Connection %s attempted to send an invalid authentication packet. It was too short. %s", connection, packet);
      connection.disconnect(DisconnectReason.custom("Authentication Error."));

      return MessageReader.fromRawBytes([0x00]);
    }

    if (packet.getLength() <= 1 + 16 + 20) {
      this.getLogger().warn("Connection %s attempted to send an invalid authentication packet. It was empty. %s", connection, packet);
      connection.disconnect(DisconnectReason.custom("Authentication Error."));

      return MessageReader.fromRawBytes([0x00]);
    }

    const uuid = `${packet.readBytes(4).getBuffer().toString("hex")}-${packet.readBytes(2).getBuffer().toString("hex")}-${packet.readBytes(2).getBuffer().toString("hex")}-${packet.readBytes(2).getBuffer().toString("hex")}-${packet.readBytes(6).getBuffer().toString("hex")}`;
    const hmacResult = packet.readBytes(20);
    const remaining = packet.readRemainingBytes();

    if (uuid === "00000000-0000-0000-0000-000000000000") {
      this.getLogger().warn("Connection %s was not logged in.", connection);
      connection.disconnect(DisconnectReason.custom("Not logged in."));

      return MessageReader.fromRawBytes([0x00]);
    }

    if (connection.getMeta<UserResponseStructure | undefined>("pgg.auth.self") !== undefined) {
      const user = connection.getMeta<UserResponseStructure>("pgg.auth.self");

      const ok = Hmac.verify(remaining.getBuffer(), hmacResult.getBuffer().toString("hex"), user.client_token);

      if (!ok) {
        this.getLogger().warn(`(normal) Connection %s, (Name: ${user.display_name}, token: ${user.client_token}) attempted to send an invalid authentication packet. Their HMAC verify failed. %s`, connection, packet);
        connection.disconnect(DisconnectReason.custom("Authentication Error."));

        return MessageReader.fromRawBytes([0x00]);
      }

      return remaining;
    }

    // cache miss

    this.fetchAndCacheUser(uuid, connection)
      .then(user => {
        const ok = Hmac.verify(remaining.getBuffer(), hmacResult.getBuffer().toString("hex"), user.client_token);

        if (!ok) {
          this.getLogger().warn(`(fetch and cache user) Connection %s, (Name: ${user.display_name}, token: ${user.client_token}) attempted to send an invalid authentication packet. Their HMAC verify failed. %s`, connection, packet);
          connection.disconnect(DisconnectReason.custom("Authentication Error."));

          return;
        }

        connection.emit("message", remaining);
      })
      .catch(err => {
        this.getLogger().warn("Connection %s attempted to send an invalid authentication packet. The API did not return a valid result (%s).", connection, err);
        connection.disconnect(DisconnectReason.custom("Authentication Error."));
      });

    return MessageReader.fromRawBytes([0x00]);
  }

  private async fetchAndCacheUser(uuid: string, connection: Connection): Promise<UserResponseStructure> {
    return new Promise((resolve, reject) => {
      this.requester.getUser(uuid).then(user => {
        connection.setMeta("pgg.auth.self", user);

        resolve(user);
      }).catch(reject);
    });
  }
  //#endregion Packet Authentication
}
