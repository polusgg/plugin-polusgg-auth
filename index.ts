import { UserResponseStructure } from "@polusgg/module-polusgg-auth-api/src/types/userResponseStructure";
import { Requester } from "@polusgg/module-polusgg-auth-api/src/requester/requester";
import { NameServicePriority } from "@polusgg/plugin-polusgg-api/src/services/name";
import { BasePlugin, PluginMetadata } from "@nodepolus/framework/src/api/plugin";
import { MessageReader } from "@nodepolus/framework/src/util/hazelMessage";
import { ServiceType } from "@polusgg/plugin-polusgg-api/src/types/enums";
import { Connection } from "@nodepolus/framework/src/protocol/connection";
import { Services } from "@polusgg/plugin-polusgg-api/src/services";
import { DisconnectReason } from "@nodepolus/framework/src/types";
import { TextComponent } from "@nodepolus/framework/src/api/text";
import { Palette } from "@nodepolus/framework/src/static";
import { Hmac } from "@nodepolus/framework/src/util/hmac";

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
};

export default class extends BasePlugin {
  private readonly requester: Requester = new Requester("https://account.polus.gg");

  constructor(config: PolusAuthConfig) {
    super(pluginMetadata, undefined, config);

    this.server.setInboundPacketTransformer(this.inboundPacketTransformer.bind(this));

    this.requester.setAuthenticationToken(process.env.NP_AUTH_TOKEN ?? config.token);

    this.server.on("player.joined", event => {
      const auth = event.getPlayer().getConnection()?.getMeta<UserResponseStructure>("pgg.auth.self");

      if (auth === undefined) {
        return;
      }

      if (auth.settings["name.color.gold"] && !auth.settings["name.color.match"]) {
        Services.get(ServiceType.Name).setForBatch(event.getLobby().getConnections(), event.getPlayer(), new TextComponent().setColor(91, 75, 27).add(event.getPlayer().getConnection()!.getName()!), NameServicePriority.High);
      }

      if (auth.settings["name.color.match"] && !auth.settings["name.color.gold"]) {
        const body = [...Palette.playerBody()[event.getPlayer().getColor()].light];

        Services.get(ServiceType.Name).setForBatch(event.getLobby().getConnections(), event.getPlayer(), new TextComponent().setColor(body[0], body[1], body[2]).add(event.getPlayer().getConnection()!.getName()!), NameServicePriority.High);
      }
    });

    this.server.on("player.color.updated", event => {
      const auth = event.getPlayer().getConnection()?.getMeta<UserResponseStructure>("pgg.auth.self");

      if (auth === undefined) {
        return;
      }

      if (auth.settings["name.color.match"] && !auth.settings["name.color.gold"]) {
        const body = [...Palette.playerBody()[event.getPlayer().getColor()].light];

        Services.get(ServiceType.Name).setForBatch(event.getPlayer().getLobby().getConnections(), event.getPlayer(), new TextComponent().setColor(body[0], body[1], body[2]).add(event.getPlayer().getConnection()!.getName()!), NameServicePriority.High);
      }
    });
  }

  //#region Packet Authentication
  inboundPacketTransformer(connection: Connection, packet: MessageReader): MessageReader {
    if (packet.readByte() !== 0x80) {
      this.getLogger().warn("Connection %s attempted to send an unauthenticated packet", connection);
      connection.disconnect(DisconnectReason.custom("Authentication Error."));

      return MessageReader.fromRawBytes([0x00]);
    }

    //1 byte for authentication magic (0x80)
    //16 bytes for client UUID
    //20 bytes for SHA1 HMAC
    if (packet.getLength() < 1 + 16 + 20) {
      this.getLogger().warn("Connection %s attempted to send an invalid authentication packet. It was too short.", connection);
      connection.disconnect(DisconnectReason.custom("Authentication Error."));

      return MessageReader.fromRawBytes([0x00]);
    }

    if (packet.getLength() <= 1 + 16 + 20) {
      this.getLogger().warn("Connection %s attempted to send an invalid authentication packet. It was empty.", connection);
      connection.disconnect(DisconnectReason.custom("Authentication Error."));

      return MessageReader.fromRawBytes([0x00]);
    }

    const uuid = `${packet.readBytes(4).getBuffer().toString("hex")}-${packet.readBytes(2).getBuffer().toString("hex")}-${packet.readBytes(2).getBuffer().toString("hex")}-${packet.readBytes(2).getBuffer().toString("hex")}-${packet.readBytes(6).getBuffer().toString("hex")}`;
    const hmacResult = packet.readBytes(20);
    const remaining = packet.readRemainingBytes();

    if (connection.getMeta<UserResponseStructure | undefined>("pgg.auth.self") !== undefined) {
      const user = connection.getMeta<UserResponseStructure>("pgg.auth.self");

      const ok = Hmac.verify(remaining.getBuffer().toString(), hmacResult.getBuffer().toString(), user.client_token);

      if (!ok) {
        this.getLogger().warn("Connection %s attempted to send an invalid authentication packet. Their HMAC verify failed.", connection);
        connection.disconnect(DisconnectReason.custom("Authentication Error."));

        return MessageReader.fromRawBytes([0x00]);
      }

      return remaining;
    }

    // cache miss

    this.fetchAndCacheUser(uuid, connection)
      .then(user => {
        const ok = Hmac.verify(remaining.getBuffer().toString(), hmacResult.getBuffer().toString(), user.client_token);

        if (!ok) {
          this.getLogger().warn("Connection %s attempted to send an invalid authentication packet. Their HMAC verify failed.", connection);
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
