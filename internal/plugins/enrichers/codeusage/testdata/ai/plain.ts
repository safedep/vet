import { pipeline } from "node:stream";
import { Client } from "./client";
import { Index } from "./search";

pipeline(source, sink, () => {});
new Client().run();
new Index("docs").query("x");
