/*
 * Background shader fields: one full-screen triangle and one fragment shader per canvas. Each field caps its pixel
 * ratio, pauses off-screen and in a hidden tab, draws a single frame under reduced motion, and hides itself (letting
 * the section's CSS gradient show) when WebGL is missing, fails to compile, or loses its context.
 */

// highp where the GPU offers it in fragment shaders; mediump drifts and bands at large coordinates on some phones
const PRELUDE =
  "#ifdef GL_FRAGMENT_PRECISION_HIGH\nprecision highp float;\n#else\nprecision mediump float;\n#endif\n" +
  "uniform vec2 r;uniform float t;uniform vec3 c0,c1,c2,c3;" +
  "float h(vec2 p){return fract(sin(dot(p,vec2(127.1,311.7)))*43758.5453);}" +
  "float n(vec2 p){vec2 i=floor(p),f=fract(p);f=f*f*(3.-2.*f);return mix(mix(h(i),h(i+vec2(1,0)),f.x),mix(h(i+vec2(0,1)),h(i+vec2(1,1)),f.x),f.y);}" +
  "float fbm(vec2 p){float v=0.,a=.5;for(int k=0;k<5;k++){v+=a*n(p);p=p*2.03+vec2(1.7,9.2);a*=.5;}return v;}";

interface FieldSpec {
  /** c0..c3 */
  colors: [string, string, string, string];
  body: string;
}

/*
 * Hero: one current. Faint stream lines run left to right and converge on a warm home glow in the lower right,
 * warming as they get close. Soft pulses travel along them; each pulse tapers to nothing at both ends, so no streak
 * ever ends in a hard edge. The headline side stays calm on wide screens; on phones the whole field is dimmer.
 */
const HERO: FieldSpec = {
  colors: ["#9fc0bb", "#0c4243", "#08302f", "#f0b65a"],
  body:
    "void main(){vec2 uv=gl_FragCoord.xy/r;float asp=r.x/r.y;vec2 p=vec2(uv.x*asp,uv.y);" +
    "float wide=smoothstep(1.3,2.2,asp);" +
    "float zone=mix(.4,smoothstep(.36,.9,uv.x),wide);" +
    "vec3 col=mix(c2,c1,.55+.45*smoothstep(0.,1.,uv.y));" +
    "vec2 home=vec2(mix(.8,.88,wide),.24);" +
    // s: how far along the current is toward home; c: how strongly the lines have converged on it
    "float s=clamp(uv.x/home.x,0.,1.);s=s*s*(3.-2.*s);float c=s*s*.82;" +
    "float L=(uv.y-home.y*c)/(1.-c);" +
    "L+=.012*sin(p.x*2.6+t*.1+L*8.)+(fbm(vec2(p.x*.5-t*.015,L*2.5))-.5)*.035;" +
    "float k=L*10.;float lane=floor(k+.5);" +
    // a thin line at each integer of k; only some lanes are drawn so it reads as a current, not stripes
    "float ln=smoothstep(.42,.5,abs(fract(k)-.5))*step(.4,h(vec2(lane,7.)));" +
    // a gaussian pulse in fract space is effectively zero at both ends, so the wrap is invisible
    "float ph=fract(uv.x*1.3-t*.045+h(vec2(lane,3.)));float pk=exp(-pow((ph-.5)*6.5,2.));" +
    "float tail=1.-smoothstep(.9,1.03,uv.x/home.x);" +
    "vec3 tint=mix(c0,c3,s*s);" +
    "col+=tint*ln*(.07+.5*pk)*zone*tail;" +
    "float dh=length((p-vec2(home.x*asp,home.y))*vec2(1.,1.3));" +
    "col+=c3*exp(-dh*dh*4.)*.17*zone;" +
    "col=mix(col,c2,smoothstep(.6,1.,uv.y)*.25);" +
    "col+=(h(mod(gl_FragCoord.xy,256.)+fract(t))-.5)*.018;" +
    "gl_FragColor=vec4(col,1.);}",
};

/* Proof band: slow rings sweep out from behind the verify output, like a probe, in the band's own wine tones. */
const PROOF: FieldSpec = {
  colors: ["#7a3d49", "#421d24", "#2e1419", "#9fd8a8"],
  body:
    "void main(){vec2 uv=gl_FragCoord.xy/r;float asp=r.x/r.y;vec2 p=vec2(uv.x*asp,uv.y);" +
    "vec3 col=mix(c2,c1,smoothstep(-.1,.9,uv.y*.6+uv.x*.4));" +
    "vec2 o=vec2((asp>1.2?.74:.5)*asp,asp>1.2?.5:.22);float d=length(p-o);" +
    "float w=fbm(p*1.4+vec2(t*.02,-t*.01))*.12;" +
    "float ring=smoothstep(.06,0.,abs(fract((d+w)*4.2-t*.05)-.5)-.42);" +
    "col=mix(col,c0,ring*.28*smoothstep(1.5,.15,d));" +
    "col+=c0*.16*exp(-d*d*2.2);" +
    "col+=c3*.025*exp(-d*d*9.);" +
    "col+=(h(mod(gl_FragCoord.xy,256.)+fract(t))-.5)*.018;" +
    "gl_FragColor=vec4(col,1.);}",
};

const SPECS: Record<string, FieldSpec> = { hero: HERO, proof: PROOF };

function rgb(hex: string): [number, number, number] {
  const v = parseInt(hex.slice(1), 16);
  return [((v >> 16) & 255) / 255, ((v >> 8) & 255) / 255, (v & 255) / 255];
}

function startField(cv: HTMLCanvasElement, spec: FieldSpec, reduceMq: MediaQueryList): void {
  const reduce = (): boolean => reduceMq.matches;
  const hide = (): void => {
    cv.style.display = "none";
  };
  const gl = cv.getContext("webgl", { antialias: false, premultipliedAlpha: false });
  if (!gl) return hide();
  const compile = (type: number, src: string): WebGLShader | null => {
    const s = gl.createShader(type);
    if (!s) return null;
    gl.shaderSource(s, src);
    gl.compileShader(s);
    if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) {
      console.warn(gl.getShaderInfoLog(s));
      return null;
    }
    return s;
  };
  const vs = compile(gl.VERTEX_SHADER, "attribute vec2 p;void main(){gl_Position=vec4(p,0.,1.);}");
  const fs = compile(gl.FRAGMENT_SHADER, PRELUDE + spec.body);
  const pr = gl.createProgram();
  if (!vs || !fs || !pr) return hide();
  gl.attachShader(pr, vs);
  gl.attachShader(pr, fs);
  gl.linkProgram(pr);
  if (!gl.getProgramParameter(pr, gl.LINK_STATUS)) {
    console.warn(gl.getProgramInfoLog(pr));
    return hide();
  }
  gl.useProgram(pr);

  gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
  const loc = gl.getAttribLocation(pr, "p");
  gl.enableVertexAttribArray(loc);
  gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
  spec.colors.forEach((hex, i) => {
    const [a, b, c] = rgb(hex);
    gl.uniform3f(gl.getUniformLocation(pr, `c${i}`), a, b, c);
  });
  const uR = gl.getUniformLocation(pr, "r");
  const uT = gl.getUniformLocation(pr, "t");

  let visible = true;
  let lost = false;
  let raf = 0;
  // start mid-flow so the first frame is not a blank field
  const t0 = performance.now() - 40000;

  const size = (): void => {
    const dpr = Math.min(window.devicePixelRatio || 1, window.innerWidth < 760 ? 1 : 1.5);
    cv.width = Math.max(1, Math.round(cv.clientWidth * dpr));
    cv.height = Math.max(1, Math.round(cv.clientHeight * dpr));
    gl.viewport(0, 0, cv.width, cv.height);
  };
  const draw = (now: number): void => {
    gl.uniform2f(uR, cv.width, cv.height);
    // wrapped so float precision never degrades on a long-open tab
    gl.uniform1f(uT, ((now - t0) / 1000) % 3600);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
    cv.classList.add("on");
  };
  const loop = (now: number): void => {
    draw(now);
    raf = visible && !document.hidden && !lost ? requestAnimationFrame(loop) : 0;
  };
  const kick = (): void => {
    if (!raf && !reduce() && visible && !document.hidden && !lost) raf = requestAnimationFrame(loop);
  };
  const onMotionPref = (): void => {
    if (reduce()) {
      cancelAnimationFrame(raf);
      raf = 0;
      draw(performance.now());
    } else kick();
  };

  size();
  if (reduce()) draw(performance.now());
  else kick();
  const ro = new ResizeObserver(() => {
    if (lost) return;
    size();
    if (reduce() || !raf) draw(performance.now());
  });
  ro.observe(cv);
  const io = new IntersectionObserver((e) => {
    visible = e.some((x) => x.isIntersecting);
    kick();
  });
  io.observe(cv);
  document.addEventListener("visibilitychange", kick);
  reduceMq.addEventListener("change", onMotionPref);
  // a lost context is not restored: the field stops for good and the CSS background takes over
  cv.addEventListener("webglcontextlost", () => {
    lost = true;
    cancelAnimationFrame(raf);
    raf = 0;
    ro.disconnect();
    io.disconnect();
    document.removeEventListener("visibilitychange", kick);
    reduceMq.removeEventListener("change", onMotionPref);
    hide();
  });
}

export function initFields(reduceMq: MediaQueryList): void {
  document.querySelectorAll<HTMLCanvasElement>("canvas[data-field]").forEach((cv) => {
    const spec = SPECS[cv.dataset.field ?? ""];
    if (spec) startField(cv, spec, reduceMq);
  });
}
