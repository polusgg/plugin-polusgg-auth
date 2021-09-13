import { UserResponseStructure } from "@polusgg/module-polusgg-auth-api/src/types/userResponseStructure";
import { Requester } from "@polusgg/module-polusgg-auth-api/src/requester/requester";
import { BasePlugin, PluginMetadata } from "@nodepolus/framework/src/api/plugin";
import { MessageReader } from "@nodepolus/framework/src/util/hazelMessage";
import { ServiceType } from "@polusgg/plugin-polusgg-api/src/types/enums";
import { Connection } from "@nodepolus/framework/src/protocol/connection";
import { Services } from "@polusgg/plugin-polusgg-api/src/services";
import { DisconnectReason } from "@nodepolus/framework/src/types";
import { Palette } from "@nodepolus/framework/src/static";
import { Hmac } from "@nodepolus/framework/src/util/hmac";
import { LobbyInstance } from "@nodepolus/framework/src/api/lobby";
import { HazelPacketType } from "@nodepolus/framework/src/types/enums";
import { EnumValue } from "@polusgg/plugin-polusgg-api/src/packets/root/setGameOption";
import { LobbyCode } from "@nodepolus/framework/src/util/lobbyCode";
import { PlayerInstance } from "@nodepolus/framework/src/api/player";

const OFFSET_MAPPINGS = [
  "UNKNOWN_NONOFFICIAL",
  "OFFICIAL",
  "SKELDJS",
];

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

    if (process.env.ENABLE_AUTHAPI_LOBBY_CODES) {
      console.log("POG");
      this.server.on("server.lobby.creating", event => {
        const authData = event.getConnection().getMeta<UserResponseStructure>("pgg.auth.self");
        let currentCode = authData.settings["lobby.code.custom"] ? authData.settings["lobby.code.custom"] : event.getLobbyCode();
        let remainingTries = 10;

        while (remainingTries > 0) {
          const fuck = this.server.getLobby(currentCode);

          if (fuck === undefined) {
            event.setLobbyCode(currentCode);

            return;
          }

          currentCode = LobbyCode.generate();
          remainingTries--;
        }

        // dream luck

        event.setDisconnectReason(DisconnectReason.custom("dream luck (or the server is full)"));
        event.cancel();
      });
    }

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
        nameService.set(event.getPlayer(), auth.display_name);
      }

      if (auth.settings["name.color.gold"] && !auth.settings["name.color.match"]) {
        nameService.set(event.getPlayer(), `<color=#DAA520>${auth.display_name}</color>`);
      }

      if (auth.settings["name.color.match"] && !auth.settings["name.color.gold"]) {
        const body = [...Palette.playerBody()[event.getPlayer().getColor()].light];

        const nameColor = `${body[0].toString(16).padStart(2, "0")}${body[1].toString(16).padStart(2, "0")}${body[2].toString(16).padStart(2, "0")}`;

        nameService.set(event.getPlayer(), `<color=#${nameColor}>${auth.display_name}</color>`);
      }
    });

    this.server.on("player.color.updated", event => {
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

        nameService.set(event.getPlayer(), `<color=#${nameColor}>${auth.display_name}</color>`);
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

      const players = event.getGame().getLobby().getPlayers();

      for (let i = 0; i < players.length; i++) {
        const player = players[i];

        this.updatePlayerCosmetics(player);
      }
    });

    this.server.on("player.left", event => {
      this.updatePlayerCosmetics(event.getPlayer());

      if (event.getPlayer().getConnection()?.isActingHost()) {
        this.syncGameData(event.getLobby(), event.getPlayer().getConnection() ? [event.getPlayer().getSafeConnection()] : []);
      }
    });

    this.server.on("lobby.host.migrated", event => {
      const newHostOptions = event.getNewHost().getMeta<UserResponseStructure>("pgg.auth.self").options;
      const lobbyOptions = Services.get(ServiceType.GameOptions).getGameOptions(event.getLobby());

      // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
      if (newHostOptions === null || newHostOptions === undefined || newHostOptions.version === undefined || newHostOptions.version === null || event.getLobby().getGame() !== undefined) {
        return;
      }

      const selectedOptions = newHostOptions[(lobbyOptions.getOption("Gamemode").getValue() as EnumValue).getSelected()] as any[] | undefined;

      if (selectedOptions) {
        for (let i = 0; i < selectedOptions.length; i++) {
          const option = selectedOptions[i];
          const actOpt = lobbyOptions.getOption(option.key);

          // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
          actOpt?.setValue(actOpt.getValue().load(option.value as any));
        }
      }
    });
  }

  updatePlayerCosmetics(player: PlayerInstance): void {
    const connection = player.getConnection();

    if (connection === undefined) {
      return;
    }

    this.requester.setUserCosmetics(connection.getMeta<UserResponseStructure>("pgg.auth.self").client_id, {
      HAT: player.getHat(),
      PET: player.getPet(),
      SKIN: player.getSkin(),
      COLOR: player.getColor(),
    });
  }

  syncGameData(lobby: LobbyInstance, syncFor: Connection[] = lobby.getActingHosts()): void {
    syncFor.forEach(host => {
      const json = Object.values(Services.get(ServiceType.GameOptions).getGameOptions(lobby).getAllOptions()).filter(option => option.getKey() !== "Gamemode").map(option => option.toJson());
      const gamemode = (Services.get(ServiceType.GameOptions).getGameOptions(lobby).getOption("Gamemode")
        .getValue() as EnumValue).getSelected();

      let o = (host.getMeta<UserResponseStructure>("pgg.auth.self").options ?? ({} as unknown as UserResponseStructure["options"]))!;

      // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
      if (o.version === undefined) {
        o = {} as unknown as any;
      }

      o.gamemode = Services.get(ServiceType.GameOptions).getGameOptions(lobby).getOption("Gamemode")
        .toJson();
      o[gamemode] = json;
      o.version = 1;

      this.requester.setUserGameOptions(host.getMeta<UserResponseStructure>("pgg.auth.self").client_id, o);
    });
  }

  //#region Packet Authentication
  inboundPacketTransformer(connection: Connection, packet: MessageReader): MessageReader {
    if (packet.peek(0) == HazelPacketType.Acknowledgement) {
      return packet;
    }

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

      if (!connection.hasMeta("pgg.auth.clientIdentification")) {
        let resolved = false;

        for (let i = 0; i < OFFSET_MAPPINGS.length; i++) {
          const MAPPING_NAME = OFFSET_MAPPINGS[i];
          const bufferCopy = new Uint8Array(hmacResult.getBuffer().length);

          hmacResult.getBuffer().copy(bufferCopy);

          Atomics.add(bufferCopy, 19, i);

          const ok = Hmac.verify(remaining.getBuffer(), Buffer.from(bufferCopy).toString("hex"), user.client_token);

          if (ok) {
            resolved = true;
            connection.setMeta("pgg.auth.clientIdentification", MAPPING_NAME);
            connection.setMeta("pgg.auth.clientIdentification.idx", i);
            console.log("CLIENT CONNECTED THROUGH", MAPPING_NAME);
            break;
          }
        }

        if (!resolved) {
          this.getLogger().warn(`(normal-noID) Connection %s, (Name: ${user.display_name}, token: ${user.client_token}) attempted to send an invalid authentication packet. Their HMAC verify failed. %s`, connection, packet);
          connection.disconnect(DisconnectReason.custom("Authentication Error."));

          return MessageReader.fromRawBytes([0x00]);
        }
      } else {
        Atomics.add(hmacResult.getBuffer(), 19, connection.getMeta<number>("pgg.auth.clientIdentification.idx"));

        const ok = Hmac.verify(remaining.getBuffer(), hmacResult.getBuffer().toString("hex"), user.client_token);

        if (!ok) {
          this.getLogger().warn(`(normal-hasID) Connection %s, (Name: ${user.display_name}, token: ${user.client_token}) attempted to send an invalid authentication packet. Their HMAC verify failed. %s`, connection, packet);
          connection.disconnect(DisconnectReason.custom("Authentication Error."));

          return MessageReader.fromRawBytes([0x00]);
        }
      }

      return remaining;
    }

    // cache miss

    this.fetchAndCacheUser(uuid, connection)
      .then(user => {
        if (!connection.hasMeta("pgg.auth.clientIdentification")) {
          let resolved = false;

          for (let i = 0; i < OFFSET_MAPPINGS.length; i++) {
            const MAPPING_NAME = OFFSET_MAPPINGS[i];
            const bufferCopy = new Uint8Array(hmacResult.getBuffer().length);

            hmacResult.getBuffer().copy(bufferCopy, 0, 0);

            Atomics.add(bufferCopy, 19, i);

            const ok = Hmac.verify(remaining.getBuffer(), Buffer.from(bufferCopy).toString("hex"), user.client_token);

            if (ok) {
              resolved = true;
              connection.setMeta("pgg.auth.clientIdentification", MAPPING_NAME);
              connection.setMeta("pgg.auth.clientIdentification.idx", i);
              console.log("CLIENT CONNECTED THROUGH", MAPPING_NAME);
              break;
            }
          }

          if (!resolved) {
            this.getLogger().warn(`(fetch and cache user-noID) Connection %s, (Name: ${user.display_name}, token: ${user.client_token}) attempted to send an invalid authentication packet. Their HMAC verify failed. %s`, connection, packet);
            connection.disconnect(DisconnectReason.custom("Authentication Error."));

            return;
          }
        } else {
          Atomics.add(hmacResult.getBuffer(), 19, connection.getMeta<number>("pgg.auth.clientIdentification.idx"));

          const ok = Hmac.verify(remaining.getBuffer(), hmacResult.getBuffer().toString("hex"), user.client_token);

          if (!ok) {
            this.getLogger().warn(`(fetch and cache user-hasID) Connection %s, (Name: ${user.display_name}, token: ${user.client_token}) attempted to send an invalid authentication packet. Their HMAC verify failed. %s`, connection, packet);
            connection.disconnect(DisconnectReason.custom("Authentication Error."));

            return;
          }
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
        this.logger.verbose(`Connection %s logged in as ${user.display_name}`, connection);
        connection.setMeta("pgg.auth.self", user);
        connection.setMeta("pgg.log.uuid", user.client_id);

        if (user.banned) {
          if (user.banned_until) {
            connection.disconnect(DisconnectReason.custom(`Banned until ${new Date(user.banned_until).toDateString()} ${new Date(user.banned_until).toTimeString()}`));
          } else {
            connection.disconnect(DisconnectReason.custom(`Banned permanently`));
          }
        }

        resolve(user);
      }).catch(reject);
    });
  }
  //#endregion Packet Authentication
}
