import { readFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { expect, it } from "vitest";
const helper = new URL(
  "../../../bridge/firmware/podman_namespace_metadata.py",
  import.meta.url,
);
it.skipIf(process.platform !== "linux")(
  "rejects duplicate JSON authority keys before descriptor/namespace effects and computes UTF8 wire size before output allocation",
  async () => {
    const code = await readFile(helper, "utf8");
    const functions = code.slice(0, code.indexOf("\ntry:\n    main()"));
    const script = `${functions}\nvalue={'controls':'\\x00\\n\\t\\\\\\"','unicode':'é☃🔬','a':[None,True,False,123]}\nencoded=json.dumps(value,ensure_ascii=False,separators=(',',':')).encode('utf8')\nassert json_wire_bytes(value)==len(encoded)\nobservations['error']={'kind':'test','message':'x'*65536}\ntry:\n emit()\nexcept ValueError as error:\n assert 'byte budget' in str(error)\nelse:\n raise AssertionError('oversized response emitted')\ntry:\n strict_json_object([('id','first'),('id','second')])\nexcept ValueError as error:\n assert 'duplicate JSON request key' in str(error)\nelse:\n raise AssertionError('duplicate authority admitted')\nprint('bounded projection controls passed')`;
    expect(
      execFileSync(
        "/usr/bin/python3",
        ["-I", "-S", "-X", "utf8", "-c", script],
        { timeout: 2000 },
      ).toString(),
    ).toBe("bounded projection controls passed\n");
  },
);
it.skipIf(process.platform !== "linux")(
  "refuses bounded malformed requests in the actual preloaded interpreter before any namespace operation and retains strict partial JSON",
  async () => {
    const code = await readFile(helper, "utf8");
    for (const input of [
      "{}",
      '{"protocol":"wrong"}',
      "{",
      "x".repeat(16385),
    ]) {
      let stdout = "";
      try {
        execFileSync(
          "/usr/bin/python3",
          ["-I", "-S", "-X", "utf8", "-c", code],
          { input },
        );
      } catch (error) {
        stdout = String((error as { stdout: Buffer }).stdout);
      }
      const result = JSON.parse(stdout);
      expect(result.status).toBe("refused");
      expect(result.stage).toBe("parent");
      expect(result.pairs).toEqual([]);
      expect(`${result.error.kind}: ${result.error.message}`).toMatch(
        /request|JSON|budget/u,
      );
    }
  },
);
it.skipIf(process.platform !== "linux")(
  "refuses actual late import/compile/exec/dlopen/thread operations using the precompiled guard, including failure serialization",
  async () => {
    const code = await readFile(helper, "utf8");
    const functions = code.slice(0, code.indexOf("\ntry:\n    main()"));
    const script = `import _thread,ctypes\n${functions}\ncompiled=compile('raise AssertionError("substituted code executed")','owned-probe','exec')\noperations=[lambda:__import__('fractions'),lambda:compile('0','probe','eval'),lambda:exec(compiled),lambda:ctypes.CDLL('/nonexistent-substitute-loader'),lambda:_thread.start_new_thread(lambda:None,())]\nstage='entry'\nfor operation in operations:\n try:\n  operation()\n except RuntimeError as error:\n  assert 'post-entry code loading/process operation refused' in str(error)\n  json.dumps({'kind':type(error).__name__,'message':str(error)}).encode('utf8')\n else:\n  raise AssertionError('late operation admitted')\nprint('five actual guard controls passed')`;
    expect(
      execFileSync(
        "/usr/bin/python3",
        ["-I", "-S", "-X", "utf8", "-c", script],
        { timeout: 2000 },
      ).toString(),
    ).toBe("five actual guard controls passed\n");
  },
);
it.skipIf(process.platform !== "linux")(
  "runs a seeded 256-case fixed-helper path/request/wire property campaign without namespace effects (seed 0x5e71)",
  async () => {
    const code = await readFile(helper, "utf8");
    const functions = code.slice(0, code.indexOf("\ntry:\n    main()"));
    const script = `import random\n${functions}\nrng=random.Random(0x5e71)\nalphabet=['a','é','☃','🔬',':','\\n','\\t','\\\\','"','\\x01']\nbase={'protocol':PROTOCOL,'id':'a'*64,'image_id':'b'*64,'graph_root':'/graph','run_root':'/run','image_root':'/graph/overlay/'+'c'*64+'/merged','helper':{'pid':1,'start_ticks':'1','user_ns':'user:[1]','mount_ns':'mnt:[2]'},'prepared':{'pid':2,'start_ticks':'2','user_ns':'user:[1]','mount_ns':'mnt:[2]'},'namespaces':{'user':{'device':'1','inode':'1'},'mount':{'device':'1','inode':'2'}},'roles':[{'role':'work','source':'/work'}]}\nfor case in range(256):\n text=''.join(rng.choice(alphabet) for _ in range(rng.randrange(1,65)))\n scalar={'case':case,'source':text,'values':[True,None,-17,text]}\n expected=len(json.dumps(scalar,ensure_ascii=False,separators=(',',':')).encode('utf8'))\n assert json_wire_bytes(scalar)==expected\n valid='/owned/'+text\n assert path(valid)==valid\n bad=rng.choice(['relative','/x/../y','/x//y','/x/','/','/nul\\0value','/surrogate\\ud800'])\n try:\n  path(bad)\n except (ValueError,UnicodeError):\n  pass\n else:\n  raise AssertionError('invalid path admitted')\n request=json.loads(json.dumps(base))\n rule=case%8\n if rule==0: request['roles'].append({'role':'work','source':'/other'})\n elif rule==1: request['roles'][0]['role']='input'\n elif rule==2: request['roles'].append({'role':'input','source':'/work/child'})\n elif rule==3: request['id']='-'+'a'*63\n elif rule==4: request['helper']['pid']=True\n elif rule==5: request['image_root']='/graph/overlay/'+('d'*63)+'/merged'\n elif rule==6: request['namespaces']['user']['inode']='-1'\n else: request['unexpected']='authority'\n try:\n  request_value(request)\n except ValueError:\n  pass\n else:\n  raise AssertionError('invalid request admitted')\n assert opened==[]\n assert observations['pairs']==[] and observations['stage']=='parent'\nprint('seed 0x5e71: 256 wire/path/request cases; no descriptor or namespace effects')`;
    expect(
      execFileSync(
        "/usr/bin/python3",
        ["-I", "-S", "-X", "utf8", "-c", script],
        { timeout: 3000 },
      ).toString(),
    ).toBe(
      "seed 0x5e71: 256 wire/path/request cases; no descriptor or namespace effects\n",
    );
  },
);
