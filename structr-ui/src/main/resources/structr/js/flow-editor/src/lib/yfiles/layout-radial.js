/****************************************************************************
 ** @license
 ** This file is part of yFiles for HTML 2.1.0.1.
 ** 
 ** yWorks proprietary/confidential. Use is subject to license terms.
 **
 ** Copyright (c) 2018 by yWorks GmbH, Vor dem Kreuzberg 28, 
 ** 72070 Tuebingen, Germany. All rights reserved.
 **
 ***************************************************************************/

import y from'./core.js';import l from'./lang.js';import'./algorithms.js';import'./layout-core.js';import'./layout-hierarchic.js';(function(a,b,c,d){'use strict';function e(b,c){var d,e=f(b),h=g(b,c),i=0;if(1===h)d=a.DE.$m11(e);else{d=a.DE.$m11(e+1);var j=new a.LMA(0);j.$m5(new a.RMA),d[0]=j,i=1}for(var k=0;k<b.$HC();k++){var l=b.$kD(k);if(l.$yx<<24>>24!==2&&l.$yx<<24>>24!==3){var j=new a.LMA(i);d[i]=j;for(var m=0,n=l.$xx.$f2;null!==n;n=n.$KRV()){var o=n.$f,p=c.$KE(o);if(p.$zx<<24>>24===0){var q=new a.UMA(i,m++,o);j.$m5(q)}else if(p.$zx<<24>>24===1){var r=new a.SMA(i,m++,p.$xA);j.$m5(r)}}i++}}return d}function f(a){for(var b=0,c=0;c<a.$HC();c++){var d=a.$kD(c);d.$yx<<24>>24!==2&&d.$yx<<24>>24!==3&&b++}return b}function g(a,b){var c;c=0;for(var d=a.$kD(0).$xx.$f2;null!==d;d=d.$KRV()){var e=d.$f;b.$KE(e).$zx<<24>>24===0&&c++}return c}function h(b){for(var c=new a.C.NQA.$F,d=b.$f1.$cUV();d.$Zx;d.$DB()){var e=d.$kx;i(b,e)||c.$m3(e)}return c}function i(a,b){return z(a,b.$f2)}function j(a){for(var b=0;b<a.$f4.$f1;b++)a.$f1.$FaV(a.$f4.$Bq(b))}function k(b,c,d,e){var f=new a.C.ZVB(null);f.$Pm=e;for(var g=f.$wBV,h=a.T.WSA.$Q(),i=!1;d.$Zx;d.$DB()){var j=d.$kx;x(b,c,j).$VpV&&(h.$Ss(j,!0),i=!0)}i&&(c.$KtW(g,h),f.$LE(c),c.$BiV(g))}function l(b,c,d){for(var e=d.$ZRV();e.$Zx;e.$DB()){var f=e.$kx,g=x(b,c,f),h=c.$nZV(f);h.$pC(),c.$IuW(f,new a.C.IRA.$G(0,0)),c.$KuW(f,new a.C.IRA.$G(0,0));for(var i=s(b,f,b.$f3.$hxV,g.$ozV),j=m(i),k=1;k<j.$xq-1;k++){var l=j.$Bq(k);h.$PJ(l.$f,l.$f1)}}}function m(b){var c,d=new a.GD,e=b.length;if(b.length<3)return d;if(3===e){c=o(b,0),d.$m(c);for(var f=0.01;f<=1;f+=0.01)c=o(b,f),d.$m(c)}else{for(var g=[null,null,null,null],h=0;h<g.length-1;h++)g[h]=b[0];for(var i=g[0],j=null,h=1;h<b.length+2;h++){g[3]=h<e?b[h]:b[e-1],d.$m(i);for(var f=1;f<=10;f++)j=n(g,f/10),d.$m(j);i=j,g[0]=g[1],g[1]=g[2],g[2]=g[3]}}return r(d,5),q(d,0,d.$xq-1,1)}function n(b,c){var d=[[Math.pow(c,3),Math.pow(c,2),c,1]],e=[[-1,3,-3,1],[3,-6,3,0],[-3,0,3,0],[1,4,1,0]];e=p(d,e);var f=[[b[0].$f],[b[1].$f],[b[2].$f],[b[3].$f]],g=[[b[0].$f1],[b[1].$f1],[b[2].$f1],[b[3].$f1]],h=p(e,f)[0][0]/6,i=p(e,g)[0][0]/6;return new a.C.IRA.$G(a.WD.$m6(h),a.WD.$m6(i))}function o(b,c){var d=Math.pow(1-c,2)*b[0].$f+2*(1-c)*c*b[1].$f+Math.pow(c,2)*b[2].$f,e=Math.pow(1-c,2)*b[0].$f1+2*(1-c)*c*b[1].$f1+Math.pow(c,2)*b[2].$f1;return new a.C.IRA.$G(d,e)}function p(c,d){for(var e=a.WD.createArrayWithTypeD1AndD2(b.lang.Number.$class,c.length,d[0].length),f=0;f<c.length;f++)for(var g=0;g<d[0].length;g++){e[f][g]=0;for(var h=0;h<c[0].length;h++)e[f][g]=e[f][g]+c[f][h]*d[h][g]}return e}function q(b,c,d,e){for(var f=0,g=c,h=new a.GD,i=g+1;i<d;++i){var j=b.$Bq(i),k=b.$Bq(c),l=b.$Bq(d),m=a.T.VQA.$T(j.$f,j.$f1,k.$f,k.$f1,l.$f,l.$f1);m>f&&(g=i,f=m)}if(f>e){var n=q(b,c,g,e),o=q(b,g,d,e);h.$m15(n),h.$m15(o)}else h.$m(b.$Bq(c)),h.$m(b.$Bq(d));return h}function r(a,b){if(!(a.$xq<3)){for(var c=a.$m14(),d=c.$m();c.$p;){var e=c.$m();if(!(d.$BZV(e)<b))break;c.$m1()}if(!(a.$xq<3))for(var f=a.$m11(a.$xq),g=f.$m2();f.$p1;){var e=f.$m2();if(!(g.$BZV(e)<b))break;f.$m1()}}}function s(b,c,d,e){var f=c.$f2,g=c.$f3,h=E(b,f).$m7(),i=E(b,g).$m7(),j=e?a.QMA.$f:a.QMA.$f2;j===a.QMA.$f?i=E(b,i).$m6():(i=E(b,i).$m8(),h=E(b,h).$m8());var k=t(b,h,i,j),l=null;if(null===k){l=u(b,h,j===a.QMA.$f?a.QMA.$f:a.QMA.$f2);for(var m=u(b,i,j===a.QMA.$f?a.QMA.$f:a.QMA.$f2),n=m.$sTV(),o=n.length-1;o>=0;o--)l.$m3(n[o])}else if(k!==i&&k!==E(b,i).$m6()&&(l=v(b,h,k,j===a.QMA.$f?a.QMA.$f:a.QMA.$f2)),k!==h&&k!==E(b,h).$m6()){var p=v(b,i,j===a.QMA.$f&&k!==b.$f?b.$f2.$OD(k).$m6():k,j===a.QMA.$f?a.QMA.$f1:a.QMA.$f2);null===l&&(l=new a.C.GSA.$F);for(var q=new a.ND.$c(l),n=p.$sTV(),o=n.length-1;o>=0;o--){var r=n[o],s=E(b,r);q.$Jr(s)||q.$Jr(s.$m6())||l.$m3(r)}}for(var w=new a.GD,o=0;o<l.$f1;o++){var r=l.$Bq(o);w.$m(b.$f1.$lZV(r))}return y(w,d)}function t(b,c,d,e){var f,g,h=null;e===a.QMA.$f?(f=u(b,c,a.QMA.$f),g=u(b,d,a.QMA.$f1)):(f=u(b,c,a.QMA.$f2),g=u(b,d,a.QMA.$f2));var i=new a.ND.$c(g);if(1===f.$f1)h=c;else if(1===g.$f1)h=d;else for(var j=f.$m1();j.$p;){var k=j.$m();if(e===a.QMA.$f){if(i.$Jr(E(b,k).$m6())||i.$Jr(k)){h=k;break}}else if(i.$Jr(k)){h=k;break}}return h}function u(b,c,d){var e=new a.C.GSA.$F;e.$m3(c);for(var f=w(b,c,d);null!==f;)e.$m3(f),f=w(b,f,d);return e}function v(b,c,d,e){for(var f=new a.C.GSA.$F,g=!1,h=c;!g;)f.$m3(h),h.equals(d)?g=!0:h=w(b,h,e);return f}function w(b,c,d){var e=E(b,c);return d===a.QMA.$f?e.$m2():d===a.QMA.$f1?e.$m4():e.$m5()}function x(b,c,d){var e=c.$EeV(a.T.FWB.EDGE_BUNDLE_DESCRIPTOR_DP_KEY);if(null!==e){var f=e.$OD(d);if(null!==f)return f}return new a.C.EWB.$G(b.$f3.$ULV)}function y(b,c){var d=a.DE.$m11(b.$xq),e=b.$xq-1;d[0]=b.$Bq(0),d[e]=b.$Bq(e);for(var f=1;f<e;f++){var g=b.$Bq(f),h=c*g.$f+(1-c)*(d[0].$f+f/e*(d[e].$f-d[0].$f)),i=c*g.$f1+(1-c)*(d[0].$f1+f/e*(d[e].$f1-d[0].$f1));d[f]=new a.C.IRA.$G(h,i)}return d}function z(b,c){return null!==E(b,c)&&E(b,c).$m3()===a.QMA.T.$f}function A(a){for(var b=a.$f1.$dUV();b.$Zx;b.$DB()){var c=b.$lx;if(!z(a,c)){var d=E(a,c),e=d.$m();if(null!==e){var f=E(a,e).$m7(),g=E(a,f).$m6(),h=E(a,f).$m8(),i=d.$m7(),j=E(a,i),k=j.$m6(),l=j.$m8();j.$m11(f),E(a,k).$m12(g),E(a,l).$m13(h),a.$f1.$mrW(i,f),a.$f1.$mrW(g,k),a.$f1.$mrW(l,h)}}}}function B(b){b.$f4=new a.C.GSA.$F;for(var c=b.$f1.$JUV(),d=0;d<c.length;d++){var e=c[d],f=b.$f1.$caV(e),g=b.$f1.$daV(e),h=E(b,e);if(null!==h.$m()){var i=b.$f1.$YTV(),j=b.$f1.$YTV(),k=b.$f1.$YTV();b.$f4.$m3(i),b.$f4.$m3(j),b.$f4.$m3(k);var l=new a.QMA.T(b,a.QMA.T.$f);l.$m14(j),l.$m16(k),l.$m15(e),h.$m15(i);var m=new a.QMA.T(b,a.QMA.T.$f);m.$m14(i),m.$m16(k),m.$m15(e);var n=new a.QMA.T(b,a.QMA.T.$f);n.$m14(k),n.$m16(k),n.$m15(e),F(b,i,l),F(b,j,m),F(b,k,n);b.$f1.$brW(k,new a.C.IRA.$G(f,g)),b.$f1.$brW(i,new a.C.IRA.$G(f-5,g-5)),b.$f1.$brW(j,new a.C.IRA.$G(f+5,g+5))}else{b.$f=b.$f1.$YTV(),b.$f4.$m3(b.$f);var o=new a.QMA.T(b,a.QMA.T.$f);o.$m14(b.$f),o.$m16(b.$f),o.$m15(e),h.$m15(b.$f),F(b,b.$f,o),b.$f1.$brW(b.$f,new a.C.IRA.$G(f,g))}}}function C(b){for(var c=b.$f1.$dUV();c.$Zx;c.$DB()){var d=new a.QMA.T(b,a.QMA.T.$f1);b.$f2.$nI(c.$lx,d)}}function D(b){for(var c=b.$f1.$EeV(a.T.LHC.$f2),d=b.$f1.$dUV();d.$Zx;d.$DB()){var e=d.$lx;E(b,e).$m9(c.$OD(e))}}function E(a,b){return a.$f2.$OD(b)}function F(a,b,c){a.$f2.$nI(b,c)}function G(a,b,c){return null===c||null===c.$OD(b)?a.$xm.$ULV:c.$OD(b)}function H(b,c,d){for(var e=null!==d,f=c.$EeV(a.T.FWB.EDGE_BUNDLE_DESCRIPTOR_DP_KEY),g=b.$f4.$ULV,h=a.T.WSA.$Q(),i=c.$cUV();i.$Zx;i.$DB()){var j=i.$kx,k=g;if(null!==f){var l=f.$OD(j);null!==l&&(k=l)}k.$sa||(e?h.$Ss(j,d.$Ks(j)):h.$Ss(j,!0))}c.$KtW(a.T.SZB.AFFECTED_EDGES_DP_KEY,h)}function I(b,c){return b.$f18||a.T.FZB.$G(c)}function J(b,c,d){if(I(b,c))for(var e=c.$dUV();e.$Zx;e.$DB()){var f=e.$lx,g=a.T.FZB.$I(c,f);if(b.$f18)for(var h=c.$m41(f),i=0;i<h.length;i++){var j=h[i];g=M(b,g,j.$VA)}d.$nI(f,c.$LYV(f)),K(f,g,c)}}function K(a,b,c){var d=c.$lZV(a),e=Math.ceil(Math.max(d.$f-b.$f,b.$f+b.$f3-d.$f)),f=Math.ceil(Math.max(d.$f1-b.$f1,b.$f1+b.$f4-d.$f1));c.$QvW(a,2*e,2*f),c.$brW(a,d)}function L(a,b,c){if(I(a,b))for(var d=b.$dUV();d.$Zx;d.$DB()){var e=d.$lx,f=b.$lZV(e);b.$EqW(e,c.$OD(e)),b.$brW(e,f)}}function M(b,c,d){if(null===c||null===d)return null===c?d:c;var e=Math.min(c.$f,d.$f),f=Math.max(c.$f+c.$f3,d.$f+d.$f3),g=Math.min(c.$f1,d.$f1),h=Math.max(c.$f1+c.$f4,d.$f1+d.$f4);return new a.C.KRA.$H(e,g,f-e,h-g)}function N(b,c){var d=a.T.NSA.$F(c),e=new a.C.NQA.$J(c.$cUV());e.$MZV(d);for(var f=e.$ZRV();f.$Zx;f.$DB())c.$kWV(f.$kx);var g;try{switch(b.$f9){case 0:g=a.T.PSA.$G(c);break;case 1:g=a.T.PSA.$K(c);break;case 2:default:g=a.T.PSA.$U(c,null)}}finally{for(var f=e.$ZRV();f.$Zx;f.$DB())c.$JXV(f.$kx)}return g}function O(b,c,d){if(b.$IyV<<24>>24===4)c.$KtW(a.T.GCC.CORE_NODES_DP_KEY,new a.T.LHC.T2(d));else{b.$f1=b.$f.$fpW(c);var e=c.$EeV(a.T.IYB.NODE_ID_DP_KEY);if(null!==e){for(var f=null,g=new a.ND.$c1(d.$xq),h=a.LD.$m5(d);h.$p;){var i=h.$m(),j=e.$OD(i);null!==j&&(null===f&&(f=j),g.$m(j))}for(var k=c.$dUV();k.$Zx;k.$DB()){var l=k.$lx,m=e.$OD(l);g.$Jr(m)?b.$f1.$WI(m):b.$f1.$sL(m,f)}}}}function P(b,c){var d=new a.C.NQA.$F,e=b.$bUV();a.T.YPA.$I(b,c,e);for(var f=b.$cUV();f.$Zx;f.$DB()){var g=f.$kx;e.$UD(g.$f3)<e.$UD(g.$f2)&&d.$uWV(g)}for(var f=d.$ZRV();f.$Zx;f.$DB())b.$xaV(f.$kx);return b.$GeV(e),d}function Q(a,b,c){var d=b.$bUV(),e=b.$aUV();S(a,b,c,d,e),Y(a,c);for(var f=0;f<a.$f10;f++)W(a,c),Y(a,c);aa(a,b,c,d,e),b.$FeV(e),b.$GeV(d)}function R(b,c,d,e){if(b.$f15){for(var f=new a.XD,g=0;g<d.length;g++)for(var h=d[g],i=h.$m3();null!==i;i=i.$KRV()){var j=i.$f;if(j instanceof a.UMA){var k=j.$m4(),l=e.$OD(k).$f1,m=l;null===f.$Aq(m)&&f.$Eq(m,new a.C.GSA.$F),f.$Aq(m).$m3(k)}}var n=a.WD.$m8(a.LD.$m4(f.$ew)[0]),o=a.WD.$m8(a.LD.$m4(f.$ew)[f.$ew.$xq-1]);b.$f2=c.$bUV();for(var h=n;h<o;h++)for(var p=f.$Aq(h),g=0;g<p.$f1;g++)for(var q=p.$Bq(g),r=e.$OD(q),s=r.$m5(),t=r.$f4,u=h+1,v=f.$Aq(u),w=0;w<v.$f1;w++){var x=v.$Bq(w),y=e.$OD(x),z=y.$m5(),A=y.$f4,B=b.$f2.$OD(x),C=0,D=c.$lZV(q),E=c.$lZV(x);null!==B&&(C=E.$BZV(c.$lZV(B))),z+A<=s+t&&(null===B||C>E.$BZV(D)&&b.$f3.$UD(q)===b.$f3.$UD(x))&&b.$f2.$nI(x,q)}c.$KtW(a.T.LHC.$f2,b.$f2)}}function S(b,c,d,e,f){for(var g=d[0].$m3().$f,h=0;h<d.length;h++)for(var i=d[h],j=i.$m3();null!==j;j=j.$KRV()){var k=j.$f;if(k instanceof a.UMA){var l=k;l.$f=b.$m11(c,l.$m4()),e.$nI(l.$m4(),l),i.$m9(Math.max(i.$m4(),l.$f/2))}else if(k instanceof a.SMA){var m=k,n=f.$OD(m.$m6());null===n&&(n=new a.C.XSA.$F,f.$nI(m.$m6(),n)),n.$m3(m)}}T(b,c,d,e,f,g),U(b,c,e,f),V(b,d)}function T(b,c,d,e,f,g){for(var h=1;h<d.length;h++)for(var i=d[h],j=i.$m3();null!==j;j=j.$KRV()){var k=j.$f;if(k instanceof a.UMA){for(var l=k,m=l.$m4(),n=c.$lZV(m),o=g,p=null,q=Number.MAX_VALUE,r=m.$eUV();r.$Zx;r.$DB()){var s=r.$kx,t=s.$VYV(m),u=e.$OD(t);if(u.$f1<l.$f1){var v=c.$lZV(t),w=n.$f-v.$f,x=n.$f1-v.$f1,y=w*w+x*x;y<q&&(o=u,q=y,p=s)}}if(l.$f1-o.$f1>1&&null!==p){for(var z=f.$OD(p),A=o,B=z.$m1();B.$p;){var C=B.$m();A.$m2(C),C.$f3=A,A=C}l.$f3=A,A.$m2(l)}else l.$f3=o,o.$m2(l)}}}function U(a,b,c,d){for(var e=b.$cUV();e.$Zx;e.$DB()){var f=e.$kx,g=d.$OD(f);if(null!==g&&null===g.$Ft.$f3){for(var h=c.$OD(f.$f2),i=c.$OD(f.$f3),j=h.$f1<i.$f1?h:i,k=h.$f1<i.$f1?i:h,l=j,m=g.$f2;null!==m;m=m.$KRV()){var n=m.$f;n.$f3=l,l.$m3(n),l=n}l.$m3(k)}}}function V(b,c){c[0].$m3().$f.$m1();for(var d=1;d<c.length;d++)for(var e=c[d],f=null,g=null,h=-1,i=-1,j=e.$m3();null!==j;){var k=j.$f;if(k.$m()){k.$m1();var l=j,m=j.$KRV();if(null!==g){var n=k.$f11.$Ft.$f2;if(i>n){for(var o=n<h,p=new a.C.XSA.$F,q=0,r=g.$f11.$f;null!==r;r=r.$JRV()){var s=r.$f;if(!(s.$f2>n))break;p.$hYV(s),q++}for(var t=k.$f11.$f2;null!==t;t=t.$KRV()){var s=t.$f;if(!(s.$f2<i))break;p.$sXV(s)}p.$vWV(new a.T.LHC.T3);for(var u=(i-n)/2,v=a.XE.$f4,w=a.XE.$f4,x=Number.MAX_VALUE,y=0,z=q,A=p.$f2;null!==A;A=A.$KRV()){var s=A.$f;if(s.$f3===k){var B=Math.abs(z-y);(B<w||B===w&&Math.abs(s.$f2-u)<x)&&(v=s.$f2,w=B,x=Math.abs(s.$f2-u)),y++}else z--}w>y&&(v=i+1);for(var A=p.$f2;null!==A;A=A.$KRV()){var s=A.$f;s.$f2<v&&s.$f3!==g?(k.$f11.$mw(s),k instanceof a.SMA&&k.$m3(s),g.$m2(s),s.$f3=g):s.$f2>=v&&s.$f3!==k&&(g.$f11.$mw(s),g instanceof a.SMA&&g.$m3(s),k.$m2(s),s.$f3=k)}if(g instanceof a.SMA&&!g.$m()){var C=g,D=g.$f3;do{D.$f11.$mw(C),D.$m3(C),C=D,D=D.$f3}while(C instanceof a.SMA&&!C.$m())}if(k instanceof a.SMA&&!k.$m()){var C=k,D=k.$f3;do{D.$f11.$mw(C),D.$m3(C),C=D,D=D.$f3}while(C instanceof a.SMA&&!C.$m())}if(g.$m1(),k.$m1(),o){for(var E=null,F=f.$JRV();null!==F;F=F.$JRV()){var C=F.$f;if(C.$m()){E=F;break}}null!==E?(l=E,m=g.$m()?f:j):k.$m()||(l=f)}else k.$m()||(l=f)}}l!==f&&(f=l,g=l.$f,h=g.$f11.$Ft.$f2,i=g.$f11.$Ds.$f2),j=m}else j=j.$KRV()}}function W(b,c){X(b,c);var d=c[0].$m3().$f;d.$f5=0,d.$f4=a.T.LHC.$f1,d.$f8=a.T.LHC.$f1;for(var e=c.length-1;e>0;e--)for(var f=c[e].$m1(),g=e<c.length-1?c[e+1].$m1():f,h=b.$dLV/180*Math.PI,i=h-2*Math.asin(f/g*Math.sin(h/2)),j=c[e].$m3();null!==j;j=j.$KRV()){var k=j.$f;if(k.$f9=k.$f/f,k.$f8=k.$f9,k.$f7>0){k.$f8=Math.max(i,k.$f9);var l=k.$f7/g;k.$f9=Math.max(k.$f9,l)}null!==k.$f3&&(k.$f3.$f7+=c[e].$m1()*k.$f9)}for(var e=0;e<c.length;e++)for(var f=c[e].$m1(),g=e<c.length-1?c[e+1].$m1():f,j=c[e].$m3();null!==j;j=j.$KRV()){var k=j.$f;if(k.$m()){var m=k.$f7/g,n=Math.max(0,(k.$f4-k.$f8)/2),o=Math.min(k.$f4,k.$f8)/m,p=k.$f5+n;if(o<=1)for(var q=k.$f11.$f2;null!==q;q=q.$KRV()){var r=q.$f;r.$f5=p;var s=r.$f9*o;r.$f4=s,p+=s}else{var t=new a.C.XSA.$G(k.$f11);t.$vWV(new a.T.LHC.T1);for(var u=k.$f4,v=k.$f7,w=t.$f2;null!==w;w=w.$KRV()){var r=w.$f;v-=r.$f9*g;var s=r.$f9*o;s>r.$f8?(s=r.$f8,u-=s,o=u*g/Math.max(1,v)):u-=s,r.$f4=s}for(var x=u/(2*k.$f11.$f1),y=k.$f5,q=k.$f11.$f2;null!==q;q=q.$KRV()){var r=q.$f;y+=x,r.$f5=y,y+=x+r.$f4}}}}}function X(a,b){for(var c=0;c<b.length;c++)for(var d=b[c].$m3();null!==d;d=d.$KRV())d.$f.$m7()}function Y(b,c){for(var d=0;d<c.length;d++){var e=c[d].$m1();if(d>0){var f=Math.max(b.$zGV,b.$ym);f=Math.max(f,c[d-1].$m4()+c[d].$m4()+b.$f19),e=Math.max(e,c[d-1].$m1()+f)}if(e=Z(b,e),c[d].$m6(e),d<c.length-1){for(var g=Z(b,e+a.T.LHC.$f),h=c[d].$m3();null!==h;h=h.$KRV()){var i=h.$f;if(i.$m()){for(var j=0,k=i.$f11.$f2;null!==k;k=k.$KRV()){var l=k.$f;j+=l.$f,l.$f4>0&&(g=Math.max(g,l.$f/l.$f4))}var m=$(b,e,j);if(g=Math.max(g,m),i.$f4>0){var n=j/ i.$f4;g=Math.max(g,n)}}}c[d+1].$m6(g)}}}function Z(b,c){var d=b.$ym;return d>0?Math.ceil(c/d-a.T.LHC.$f)*d:c}function $(b,c,d){if(0===d)return 0;if(c<a.T.LHC.$f||b.$dLV+a.T.LHC.$f>360)return d/a.T.LHC.$f1;for(var e=b.$dLV*Math.PI/360,f=Math.sin(e)/d,g=d/(c+d/(e+Math.sin(e))),h=Number.MAX_VALUE;;){var i=_(b,c,e,f,g),j=Math.abs(g-i);if(j>=h)break;if(j<a.T.LHC.$f){g=i;break}g=i,h=j}return d/g}function _(a,b,c,d,e){var f=c-e/2;return e+(Math.sin(f)-b*d*e)/(Math.cos(f)/2+d*b)}function aa(b,c,d,e,f){for(var g=c.$EeV(a.T.LHC.NODE_INFO_DP_KEY),h=0;h<d.length;h++)for(var i=d[h],j=i.$m3();null!==j;j=j.$KRV()){var k=j.$f;k instanceof a.UMA?ba(b,c,d,k,g):k instanceof a.SMA&&0===k.$f4&&ca(b,d,j)}b.$f15&&R(b,c,d,e),da(b,c,d,e,f)}function ba(b,c,d,e,f){var g=e.$m4(),h=d[e.$f1].$m1(),i=a.T.LHC.T.$m1(h,e.$m5());if(c.$brW(g,i),null!==f)if(a.C.URA.isInstance(f)){var j=new a.C.MHC;j.$f2=e.$f1,j.$f=h,j.$f4=i,j.$f3=a.T.VQA.$F(e.$f5)-90,j.$f1=a.T.VQA.$F(e.$f4),f.$nI(g,j)}else{var j=f.$OD(g);null!==j&&(j.$f2=e.$f1,j.$f=h,j.$f4=i,j.$f3=a.T.VQA.$F(e.$f5)-90,j.$f1=a.T.VQA.$F(e.$f4))}}function ca(b,c,d){var e=d.$f;e.$m4(c);for(var f=c[e.$f1],g=c[e.$f1].$m1(),h=null,i=null,j=1,k=f.$m7(d);null!==k&&k!==d;k=f.$m7(k)){var l=k.$f;if(l.$f4>0){h=k;break}l instanceof a.SMA&&l.$m4(c),j++}for(k=f.$m8(d);null!==k&&k!==d;k=f.$m8(k)){var l=k.$f;if(l.$f4>0){i=k;break}l instanceof a.SMA&&l.$m4(c),j++}var m,n,o=h.$f,p=i.$f,q=b.$f19/(2*g),r=o instanceof a.UMA?o.$f/(2*g):q,s=p instanceof a.UMA?p.$f/(2*g):q,t=o===p?2*Math.PI:a.T.LHC.T.$m7(o.$m5(),p.$m5(),!0);t<r+s?n=m=o.$m5()+r-(r+s-t)/2:(m=o.$m5()+r,n=p.$m5()-s);var u=a.T.LHC.T.$m7(m,n,!0);j>1&&u<q*(j-1)&&(q=u/(j-1));for(var v=f.$m8(h),w=f.$m7(i);j>0;){var x=v.$f,y=x.$m8();if(u<0&&(u=0,n=m),1===j){var z;z=a.T.LHC.T.$m5(m,y,n)?y:a.T.LHC.T.$m7(n,y,!0)<a.T.LHC.T.$m7(y,m,!0)?n:m,x.$f5=z-a.T.LHC.$f/2,x.$f4=a.T.LHC.$f;break}var A,B,C=Math.max(0,u-(j-1)*q),D=C/j,E=a.T.LHC.T.$m2(m+D),F=a.T.LHC.T.$m7(n,m,!0)/2+a.T.LHC.$f,G=a.T.LHC.T.$m2(m-F);if(a.T.LHC.T.$m5(G,y,E)){var z=a.T.LHC.T.$m5(m,y,E)?y:m;x.$f5=z-a.T.LHC.$f/2,x.$f4=a.T.LHC.$f;var H=a.T.LHC.T.$m2(z+q);u-=a.T.LHC.T.$m7(m,H,!0),m=H,j--,v=f.$m8(v)}else{var I=a.T.LHC.T.$m7(E,y,!0),J=a.T.LHC.T.$m7(y,m,!0);I<J?(A=I,B=E):(A=J,B=m);var K,L,M=w.$f,N=M.$m8(),O=a.T.LHC.T.$m2(n-D);if(a.T.LHC.T.$m5(O,N,G+2*a.T.LHC.$f)){var z=a.T.LHC.T.$m5(O,N,n)?N:n;M.$f5=z-a.T.LHC.$f/2,M.$f4=a.T.LHC.$f;var P=a.T.LHC.T.$m2(z-q);u-=a.T.LHC.T.$m7(P,n,!0),n=P,j--,w=f.$m7(w)}else{var I=a.T.LHC.T.$m7(N,O,!0),Q=a.T.LHC.T.$m7(n,N,!0);if(I<Q?(K=I,L=O):(K=Q,L=n),A<K){x.$f5=B-a.T.LHC.$f/2,x.$f4=a.T.LHC.$f;var H=a.T.LHC.T.$m2(B+q);u-=a.T.LHC.T.$m7(m,H,!0),m=H,j--,v=f.$m8(v)}else{M.$f5=L-a.T.LHC.$f/2,M.$f4=a.T.LHC.$f;var P=a.T.LHC.T.$m2(L-q);u-=a.T.LHC.T.$m7(P,n,!0),n=P,j--,w=f.$m7(w)}}}}}function da(b,c,d,e,f){for(var g=a.T.A.$I(c),h=a.T.LHC.$f3,i=c.$cUV();i.$Zx;i.$DB()){var j=i.$kx;a.T.AZB.$h(c,j,!0),0===h--&&(g.$XRV(),h=a.T.LHC.$f3);var k=new a.C.XSA.$F,l=e.$OD(j.$f2),m=e.$OD(j.$f3),n=f.$OD(j);if(k.$m3(l),null!==n)if(l.$f1<m.$f1)k.$MXV(n);else for(var o=n.$f;null!==o;o=o.$JRV())k.$m3(o.$f);k.$m3(m);var p=l.$f1===m.$f1,q=ea(b,p,b.$DEV<<24>>24);q instanceof a.JMA&&(q.$f5=b.$f21,q.$f2=b.$f11,q.$p=b.$f8);var r=q.$m(k,d);if(!a.LD.$m1(r))for(var s=c.$m37(j),t=a.LD.$m5(r);t.$p;){var u=t.$m();s.$PJ(u.$f,u.$f1)}}}function ea(b,c,d){switch(d){case a.T.LHC.$f4:case 1:case a.T.LHC.$f6:case a.T.LHC.$f7:case a.T.LHC.$f5:return b.$f16[d];case 5:default:return c?b.$f16[a.T.LHC.$f7]:b.$f16[a.T.LHC.$f5]}}function fa(b,c){var d=b.$EeV(a.T.FWB.EDGE_BUNDLE_DESCRIPTOR_DP_KEY);if(null===d)return c.$ULV.$sa?b.$rd:0;for(var e=0,f=b.$cUV();f.$Zx;f.$DB()){var g=d.$OD(f.$kx);e=null!==g?g.$sa?e+1:e:c.$ULV.$sa?e+1:e}return e}b.lang.addMappings('yFiles-for-HTML-Complete-2.1.0.1-Evaluation (Build 1c6e00a8d772-04/06/2018)',{_$_wwc:['radius','$UY'],_$_rnd:['sectorSize','$fi'],_$_zqd:['circleIndex','$gk'],_$_ard:['sectorStart','$hk'],_$_xud:['centerOffset','$tm'],_$_bvd:['edgeBundling','$xm'],_$_cvd:['layerSpacing','$ym'],_$_ope:['centerNodesDpKey','$HyV'],get _$_ppe(){return['layeringStrategy','$IyV',b.lang.decorators.Type('yfiles._R.C.JHC',4)]},_$_qpe:['minimumBendAngle','$JyV'],get _$_pte(){return['centerNodesPolicy','$RAV',b.lang.decorators.Type('yfiles._R.C.IHC',4)]},_$_zxe:['considerNodeLabels','$fCV'],get _$_rcf(){return['edgeRoutingStrategy','$DEV',b.lang.decorators.Type('yfiles._R.C.KHC',4)]},_$_mgf:['minimumLayerDistance','$zGV'],_$_kpf:['maximumChildSectorAngle','$dLV'],_$_wtf:['minimumNodeToNodeDistance','$rNV'],_$_xzl:['CenterNodesPolicy','IHC'],_$_yzl:['LayeringStrategy','JHC'],_$_zzl:['EdgeRoutingStrategy','KHC'],_$_aam:['RadialLayout','LHC'],_$_bam:['RadialLayoutNodeInfo','MHC'],_$$_yna:['yfiles.radial','yfiles._R.T','yfiles._R.C']});var ga=['Minimal Bend Angle must not be bigger the 90','Minimal Bend Angle must be positive','y.layout.radial.EDGE_BUNDLING_DPKEY','No DataProvider holding EdgeBundling instance registered','y.layout.radial.bundles.PARENTS_DPKEY','Distance may not be negative','Spacing value may not be negative','Minimal layer distance may not be negative','Child sector size must be less or equal to 360 degrees','Child sector size may not be negative','Spacing must be greater than 0','Minimum Bend Angle must be less or equal to 90 degrees','Minimum Bend Angle must be positive','No valid center node policy','Invalid data provider key: ','Invalid layering strategy','Invalid edge routing strategy','NodeInfoDpKey'];b.lang.module('_$$_yna',function(c){c._$_aam=new b.lang.ClassDefinition(function(){return{$extends:a.C.EZB,constructor:function(){a.C.EZB.call(this),this.$$init$$1(),this.$f6=a.T.IYB.AFFECTED_NODES_DP_KEY,this.$f4=new a.C.FWB.$F,this.$FKV=!0,this.$EJV=!1,this.$f=new a.C.EDC,this.$f.$dGV=150,this.$f13=new a.PMA(this.$f.$aGV),this.$f.$aGV=this.$f13,this.$f16=[new a.WMA,new a.OMA,new a.NMA,new a.VMA.$c(1),new a.VMA]},$f13:null,$f20:10,$f5:25,$f14:100,$f17:180,$f9:null,$f6:null,$f7:null,$f12:null,$f16:null,$f21:!1,$f:null,$f10:2,$f11:25,$f8:5,$f19:50,$f1:null,$f18:!1,$f4:null,$f3:null,$f2:null,$f15:!1,_$_wtf:{get:function(){return this.$f20},set:function(b){if(!(b>=0))throw a.QE.$m18(ga[5]);this.$f20=b}},_$_cvd:{get:function(){return this.$f5},set:function(b){if(!(b>=0))throw a.QE.$m18(ga[6]);this.$f5=b}},_$_mgf:{get:function(){return this.$f14},set:function(b){if(!(b>=0))throw a.QE.$m18(ga[7]);this.$f14=b}},_$_kpf:{get:function(){return this.$f17},set:function(b){if(b<0)throw a.QE.$m18(ga[9]);if(b>360)throw a.QE.$m18(ga[8]);this.$f17=b}},'$p!':{get:function(){return this.$f11},set:function(b){if(!(b>0))throw a.QE.$m18(ga[10]);this.$f11=b}},_$_qpe:{get:function(){return this.$f8},set:function(b){if(b<0)throw a.QE.$m18(ga[12]);if(b>90)throw a.QE.$m18(ga[11]);this.$f8=b}},'$p1!':{get:function(){return this.$f21},set:function(a){this.$f21=a}},_$_pte:{get:function(){return this.$f9},set:function(b){switch(b<<24>>24){case 0:case 1:case 2:case 3:this.$f9=b<<24>>24;break;default:throw a.QE.$m18(ga[13])}}},_$_ope:{get:function(){return this.$f6},set:function(b){if(null===b)throw a.QE.$m18(ga[14]+null);this.$f6=b}},_$_ppe:{get:function(){return this.$f7},set:function(b){switch(b<<24>>24){case 4:case 1:this.$f7=b<<24>>24;break;default:throw a.QE.$m18(ga[15])}}},_$_rcf:{get:function(){return this.$f12},set:function(b){switch(b<<24>>24){case 1:case 5:this.$f12=b<<24>>24;break;default:throw a.QE.$m18(ga[16])}}},_$_zxe:{get:function(){return this.$f18},set:function(a){this.$f18=a}},$fMV:{set:function(a){this.$f42=a}},$ngV:function(b){if(!b.$TT){var c=b.$EeV(a.T.HAC.SOURCE_GROUP_ID_DP_KEY);b.$BiV(a.T.HAC.SOURCE_GROUP_ID_DP_KEY);var d=b.$EeV(a.T.HAC.TARGET_GROUP_ID_DP_KEY);b.$BiV(a.T.HAC.TARGET_GROUP_ID_DP_KEY),this.$f15=fa(b,this.$f4)>1,this.$f3=a.T.WSA.$R();var e=null,f=null;this.$f15&&(f=b.$EeV(a.QMA.$f3),b.$KtW(a.QMA.$f3,a.T.TSA.$S(this.$xm)),this.$nNV&&this.$WCV instanceof a.C.SZB&&(e=b.$EeV(a.T.SZB.AFFECTED_EDGES_DP_KEY),H(this,b,e)));var g=b.$bUV();J(this,b,g);var h=null,i=this.$m2(b);if(i.$aSV()||(O(this,b,i),h=P(b,i)),this.$f.$sOV=this.$IyV<<24>>24,this.$f.$LE(b),Q(this,b,this.$f13.$f),null!==h)for(;!h.$aSV();){var j=h.$VSV();a.T.AZB.$P(b.$nZV(j)),b.$xaV(j)}if(this.$IyV<<24>>24===4&&b.$BiV(a.T.GCC.CORE_NODES_DP_KEY),null!==this.$f1&&(this.$f1.$aC(),this.$f1=null),this.$f13.$m(),L(this,b,g),b.$GeV(g),this.$f15){for(var k=b.$EeV(a.T.FWB.EDGE_BUNDLE_DESCRIPTOR_DP_KEY),l=new a.C.VSA(b),m=b.$cUV();m.$Zx;m.$DB()){var j=m.$kx;G(this,j,k).$sa||l.$qWV(j)}new a.QMA().$LE(b),l.$HTV(),b.$GeV(this.$f2),b.$BiV(a.T.LHC.$f2)}null!==c&&(b.$KtW(a.T.HAC.SOURCE_GROUP_ID_DP_KEY,c),c=null),null!==d&&(b.$KtW(a.T.HAC.TARGET_GROUP_ID_DP_KEY,d),d=null),this.$f15&&(b.$BiV(a.QMA.$f3),this.$nNV&&this.$WCV instanceof a.C.SZB&&b.$BiV(a.T.SZB.AFFECTED_EDGES_DP_KEY)),null!==f&&b.$KtW(a.QMA.$f3,f),null!==e&&b.$KtW(a.T.SZB.AFFECTED_EDGES_DP_KEY,e)}},'$m2!':function(b){var c=new a.C.GSA.$F;if(3===this.$f9){var d=b.$EeV(this.$HyV);if(null!==d)for(var e=b.$dUV();e.$Zx;e.$DB())d.$Ks(e.$lx)&&c.$m3(e.$lx);if(!c.$aSV())return c}var f=a.T.ORA.$N(b,this.$f3);if(f>1){for(var g=new a.C.USA(b,this.$f3),h=0;h<f;h++)g.$vgV(h),c.$m3(N(this,b));g.$FTV()}else c.$m3(N(this,b));return c},'$m11!':function(a,b){var c=a.$AYV(b),d=a.$mZV(b),e=1;return(c>0||d>0)&&(e=Math.sqrt(c*c+d*d)),e+=this.$rNV},_$_bvd:{get:function(){return this.$f4}},$$init$$1:function(){this.$f9=2,this.$f7=4,this.$f12=5},$static:{NODE_INFO_DP_KEY:null,$f4:0,$f6:2,$f7:3,$f5:4,$f:0.0001,$f1:null,$f3:50,$f2:ga[4],T2:new b.lang.ClassDefinition(function(){return{$extends:a.C.SSA,$final:!0,constructor:function(b){a.C.SSA.call(this),this.$f=b},'$Ks!':function(a){return this.$f.$Jr(a)},$f:null}}),T3:new b.lang.ClassDefinition(function(){return{$final:!0,$with:[a.C.KTA],constructor:function(){},'$sw!':function(a,b){var c=a,d=b,e=c.$f2-d.$f2;return e<0?-1:e>0?1:0}}}),T1:new b.lang.ClassDefinition(function(){return{$final:!0,$with:[a.C.KTA],constructor:function(){},'$sw!':function(a,b){var c=a,d=b,e=c.$f9-d.$f9;return e>0?-1:e<0?1:0}}}),T:new b.lang.ClassDefinition(function(){return{$final:!0,constructor:function(a,b){this.$f1=a,this.$f=b},$f1:0,$f:0,'$m!':function(b){return a.T.LHC.T.$m3(this.$f,b.$f)},$static:{'$m7!':function(b,c,d){var e=c-b;return d&&e<0?e+=a.T.LHC.$f1:!d&&e>0&&(e-=a.T.LHC.$f1),e},'$m3!':function(a,b){var c=b-a;return 0<=c&&c<=Math.PI||c<0&&c<-Math.PI},'$m6!':function(b,c,d){return a.T.LHC.T.$m5(b.$f,c.$f,d.$f)},'$m5!':function(a,b,c){return a<=b&&b<=c||c<a&&(a<b||b<c)},'$m4!':function(b,c,d){var e=(b.$f1+c.$f1)/2,f=a.T.LHC.T.$m7(b.$f,c.$f,d),g=a.T.LHC.T.$m2(b.$f+f/2);return new a.T.LHC.T(e,g)},'$m2!':function(b){return b<0?b+=a.T.LHC.$f1:b>=a.T.LHC.$f1&&(b-=a.T.LHC.$f1),b},'$m1!':function(b,c){var d=Math.sin(c)*b,e=Math.cos(c)*b;return new a.C.IRA.$G(d,e)},'$m!':function(b,c){var d=Math.atan2(c,b),e=b*b+c*c,f=e>0?Math.sqrt(e):0;return new a.T.LHC.T(f,d)}}}}),$clinit:function(){a.T.LHC.NODE_INFO_DP_KEY=new a.C.LQA(a.C.MHC.$class,a.C.LHC.$class,ga[17]),a.T.LHC.$f1=2*Math.PI}}}})}),b.lang.module('_$$_yna',function(a){a._$_xzl=new b.lang.EnumDefinition(function(){return{DIRECTED:0,CENTRALITY:1,WEIGHTED_CENTRALITY:2,CUSTOM:3}})}),b.lang.module('_$$_yna',function(a){a._$_yzl=new b.lang.EnumDefinition(function(){return{BFS:4,HIERARCHICAL:1}})}),b.lang.module('_$$_yna',function(a){a._$_zzl=new b.lang.EnumDefinition(function(){return{POLYLINE:1,ARC:5}})}),b.lang.module('_$$_yna',function(a){a._$_bam=new b.lang.ClassDefinition(function(){return{constructor:function(){},$f2:0,$f:0,$f4:null,$f3:0,$f1:0,_$_zqd:{get:function(){return this.$f2}},_$_wwc:{get:function(){return this.$f}},_$_xud:{get:function(){return this.$f4}},_$_ard:{get:function(){return this.$f3}},_$_rnd:{get:function(){return this.$f1}}}})}),b.lang.module('yfiles._R',function(c){c.JMA=new b.lang.ClassDefinition(function(){return{$abstract:!0,$with:[a.MMA],constructor:function(){this.$f3=Math.cos(this.$f*Math.PI/180)},$f6:!0,$f5:!1,$f2:25,$f:5,$f3:0,'$p2!':{get:function(){return this.$f5},set:function(a){this.$f5=a}},'$p1!':{get:function(){return this.$f2},set:function(a){this.$f2=a}},'$p!':{get:function(){return this.$f},set:function(b){if(b<0)throw a.QE.$m18(ga[1]);if(b>90)throw a.QE.$m18(ga[0]);this.$f=b,this.$f3=Math.cos(this.$f*Math.PI/180)}},'$m6!':function(b,c){for(var d=new a.C.XSA.$F,e=null,f=a.LD.$m5(b);f.$p;){var g=f.$m(),h=g.$f1,i=c[h].$m1(),j=g.$m5(),k=this.$f5?c[h].$m4():0;if(null!==e){if(this.$f5&&(!this.$f6||e.$f1>0)&&Math.abs(j-e.$m5())>a.T.LHC.$f){var l=c[e.$f1].$m1(),m=c[e.$f1].$m4(),n=e.$f1>h?l-m:l+m;d.$m3(new a.T.LHC.T(n,e.$m5()))}var o=e.$f1===h;if(o){var p;if(h+1<c.length){var q=this.$f5?c[h+1].$m4():0;p=(i+k+c[h+1].$m1()-q)/2}else{var m=this.$f5?c[h-1].$m4():0,l=c[h-1].$m1();p=i+k+(i-k-(l+m))/2}var r=e.$m5(),s=a.T.LHC.T.$m3(r,j),t=a.T.LHC.T.$m7(r,j,s)/2,u=a.T.LHC.T.$m2(r+t);d.$m3(new a.T.LHC.T(p,u))}if(this.$f5&&Math.abs(j-e.$m5())>a.T.LHC.$f)if(o)d.$m3(new a.T.LHC.T(i+k,j));else if(!this.$f6||e.$f1>0&&h>0){var n=e.$f1<h?i-k:i+k;d.$m3(new a.T.LHC.T(n,j))}}d.$m3(new a.T.LHC.T(i,j)),e=g}if(d.$f1>2){var v=d.$f2,w=v.$f.$f,x=v.$f.$f1,y=v.$KRV(),r=y.$f.$f;0===x&&(w=r);for(var z=y.$KRV();null!==z;z=z.$KRV()){var j=z.$f.$f;Math.abs(w-r)<a.T.LHC.$f&&Math.abs(r-j)<a.T.LHC.$f?d.$KaV(y):w=r,y=z,r=j}}return d},'$m5!':function(a){if(a.$f1>2)for(var b=a.$f2,c=b.$f,d=b.$KRV(),e=d.$f,f=c.$f-e.$f,g=c.$f1-e.$f1,h=d.$KRV();null!==h;h=h.$KRV()){var i=h.$f,j=e.$f-i.$f,k=e.$f1-i.$f1,l=(j*f+k*g)/(Math.sqrt(j*j+k*k)*Math.sqrt(f*f+g*g));l>this.$f3?(a.$KaV(d),f=c.$f-i.$f,g=c.$f1-i.$f1):(c=e,f=j,g=k),d=h,e=i}},$m:b.lang.Abstract}})}),b.lang.module('yfiles._R',function(c){c.UMA=new b.lang.ClassDefinition(function(){return{$extends:a.TMA,$final:!0,constructor:function(b,c,d){a.TMA.call(this,c,b),this.$f6=d},$f6:null,'$m4!':function(){return this.$f6}}})}),b.lang.module('yfiles._R',function(c){c.TMA=new b.lang.ClassDefinition(function(){return{constructor:function(a,b){this.$f2=a,this.$f1=b},$f:0,$f5:0,$f4:0,$f7:0,$f9:0,$f8:0,$f1:0,$f2:0,$f3:null,$f11:null,$f12:null,'$m5!':function(){return this.$f5+this.$f4/2},'$m7!':function(){this.$f5=0,this.$f4=0,this.$f9=0,this.$f8=0,this.$f7=0},'$m2!':function(b){null===this.$f11&&(this.$f11=new a.C.XSA.$F),this.$f11.$m3(b)},'$m3!':function(b){null===this.$f12&&(this.$f12=new a.C.XSA.$F),this.$f12.$m3(b)},'$m!':function(){return null!==this.$f11&&!this.$f11.$aSV()},'$m1!':function(){null!==this.$f11&&this.$f11.$vWV(new a.TMA.T)},$static:{T:new b.lang.ClassDefinition(function(){return{$final:!0,$with:[a.C.KTA],constructor:function(){},'$sw!':function(a,b){var c=a,d=b,e=c.$f2-d.$f2;return e<0?-1:e>0?1:0}}})}}})}),b.lang.module('yfiles._R',function(c){c.SMA=new b.lang.ClassDefinition(function(){return{$extends:a.TMA,$final:!0,constructor:function(b,c,d){a.TMA.call(this,c,b),this.$f6=d},$f6:null,$f10:0,'$m6!':function(){return this.$f6},'$m8!':function(){return this.$f10},'$m4!':function(b){var c=b[this.$f1].$m1(),d=this.$f3.$m5(),e=b[this.$f3.$f1].$m1(),f=this;do{f=null!==f.$f12?f.$f12.$Ft:f.$f11.$Ft}while(0===f.$f4);var g=f.$m5(),h=b[f.$f1].$m1(),i=a.T.LHC.T.$m3(d,g),j=a.T.LHC.T.$m7(d,g,i),k=(c-e)/(h-e);this.$f10=a.T.LHC.T.$m2(d+k*j)}}})}),b.lang.module('yfiles._R',function(c){c.RMA=new b.lang.ClassDefinition(function(){return{$extends:a.TMA,$final:!0,constructor:function(){a.TMA.call(this,0,0)}}})}),b.lang.module('yfiles._R',function(c){c.PMA=new b.lang.ClassDefinition(function(){return{$final:!0,$with:[a.C.UDC],constructor:function(a){this.$f1=a},$f1:null,$f:null,'$p1!':{get:function(){return this.$f1}},'$p!':{get:function(){return this.$f}},'$m!':function(){this.$f=null},'$TN!':function(a,b,c,d){this.$f1.$TN(a,b,c,d),0===b.$HC()?this.$f=[]:this.$f=e(b,c)}}})}),b.lang.module('yfiles._R',function(c){c.VMA=new b.lang.ClassDefinition(function(){return{$extends:a.KMA,$final:!0,constructor:{default:function(){a.KMA.call(this)},$c:function(b){a.KMA.call(this),this.$f1=!1,this.$f4=b}},$f1:!0,$f4:0.5,'$m1!':function(){return this.$f1},'$m3!':function(a){this.$f1=a},'$m2!':function(){return this.$f4},'$m4!':function(a){this.$f4=a},'$m7!':function(b,c,d,e,f){var g=c.$m(d),h=d.$f1-c.$f1,i=a.T.LHC.T.$m7(c.$f,d.$f,g);if(!(Math.abs(i)<a.T.LHC.$f)){var j,k,l,m,n=Math.abs(h)+(c.$f1+h/2)*Math.abs(i),o=Math.max(1,a.WD.$m6(Math.floor(n/this.$f2))),p=0;if(e!==f)j=1/(o+1),k=e?0:o,l=e?o:0,p=e?1:0,m=this.$f1?0.5-Math.min(2*Math.abs(i)/Math.PI,0.5):1-this.$f4;else if(j=2/(o+1),k=o/2|0,l=o-k,h/=2,i/=2,this.$f1)if(0===h)m=1-Math.min(1.5*Math.abs(i)/Math.PI,1);else if(0===i)m=1;else{var q=(c.$f1+h/2)*i;m=Math.min(1,Math.abs(h/q*a.VMA.$f*Math.PI/ i))}else m=1-this.$f4;for(var r=0;r<k;r++){p+=j;var s,t,u=p*Math.PI/2,v=1-(m*(1-p)+(1-m)*Math.cos(u)),w=m*p+(1-m)*Math.sin(u);e?(s=v,t=w):(s=w,t=v);var x=c.$f1+s*h,y=c.$f+t*i;b.$m3(a.T.LHC.T.$m1(x,y))}p=2-p;for(var r=0;r<l;r++){p-=j;var s,t,u=p*Math.PI/2,v=1-(m*(1-p)+(1-m)*Math.cos(u)),w=m*p+(1-m)*Math.sin(u);f?(s=v,t=w):(s=w,t=v);var x=d.$f1-s*h,y=d.$f-t*i;b.$m3(a.T.LHC.T.$m1(x,y))}}},$static:{$f:0.125}}})}),b.lang.module('yfiles._R',function(c){c.OMA=new b.lang.ClassDefinition(function(){return{$extends:a.JMA,$final:!0,constructor:function(){a.JMA.call(this)},'$m!':function(b,c){if(b.$xq<3)return a.KD.$f1;var d=a.OMA.$super.$m6.call(this,b,c);if(d.$f1<3)return a.KD.$f1;var e=new a.C.XSA.$F,f=d.$m1();f.$m();for(var g=0;g<d.$f1-2;g++){var h=f.$m();e.$m3(a.T.LHC.T.$m1(h.$f1,h.$f))}return this.$m5(e),e}}})}),b.lang.module('yfiles._R',function(c){c.NMA=new b.lang.ClassDefinition(function(){return{$extends:a.KMA,$final:!0,constructor:function(){a.KMA.call(this)},'$m7!':function(b,c,d,e,f){var g=c.$m(d),h=d.$f1-c.$f1,i=a.T.LHC.T.$m7(c.$f,d.$f,g);if(!(Math.abs(i)<a.T.LHC.$f))for(var j=Math.abs(h)+(c.$f1+h/2)*Math.abs(i),k=Math.max(1,a.WD.$m6(Math.floor(j/this.$f2))),l=h/(k+1),m=i/(k+1),n=c.$f1,o=c.$f,p=0;p<k;p++)n+=l,o+=m,b.$m3(a.T.LHC.T.$m1(n,o))}}})}),b.lang.module('yfiles._R',function(a){a.MMA=new b.lang.InterfaceDefinition(function(){return{$m:b.lang.Abstract}})}),b.lang.module('yfiles._R',function(c){c.LMA=new b.lang.ClassDefinition(function(){return{$final:!0,constructor:function(b){this.$f=b,this.$f1=new a.C.XSA.$F},$f:0,$f2:0,$f3:0,$f1:null,'$m!':function(){return this.$f},'$m1!':function(){return this.$f2},'$m6!':function(a){this.$f2=a},'$m4!':function(){return this.$f3},'$m9!':function(a){this.$f3=a},'$m3!':function(){return this.$f1.$f2},'$m2!':function(){return this.$f1.$f},'$m8!':function(a){return null!==a.$KRV()?a.$KRV():this.$f1.$f2},'$m7!':function(a){return null!==a.$JRV()?a.$JRV():this.$f1.$f},'$m5!':function(a){this.$f1.$m3(a)}}})}),b.lang.module('yfiles._R',function(c){c.KMA=new b.lang.ClassDefinition(function(){return{$extends:a.JMA,$abstract:!0,constructor:function(){a.JMA.call(this)},'$m!':function(b,c){for(var d=this.$m6(b,c),e=new a.C.XSA.$F,f=null,g=null,h=d.$f2;null!==h;h=h.$KRV()){var i=h.$f;if(null!==g){var j=!0;null!==f&&(j=f.$f1<g.$f1);var k=g.$f1<i.$f1,l=!1;if(null!==h.$KRV()){var m=h.$KRV().$f;l=k!==i.$f1<m.$f1}(!this.$f6||0!==g.$f1&&0!==i.$f1)&&(null!==f&&e.$m3(a.T.LHC.T.$m1(g.$f1,g.$f)),this.$m7(e,g,i,j!==k,l))}f=g,g=i}return this.$m5(e),e},$m7:b.lang.Abstract}})}),b.lang.module('yfiles._R',function(c){c.QMA=new b.lang.ClassDefinition(function(){return{$final:!0,$with:[a.C.HYB],constructor:function(){},$f2:null,$f1:null,$f:null,$f3:null,$f4:null,'$LE!':function(b){this.$f1=b;var c=this.$f1.$EeV(a.QMA.$f3);if(null===c||!(c.$OD(b)instanceof a.C.FWB))throw a.QE.$m28(ga[3]);this.$f3=c.$OD(b),this.$f2=b.$bUV();var d=new a.C.VSA(b);C(this),D(this),B(this),A(this),d.$HTV(),l(this,b,h(this)),j(this),k(this,this.$f1,b.$cUV(),4),b.$GeV(this.$f2)},$static:{$f:0,$f1:1,$f2:2,$f3:ga[2],T:new b.lang.ClassDefinition(function(){return{$final:!0,constructor:function(a,b){this.$f5=a,this.$f3=b},$f3:0,$f1:0,$f8:null,$f7:null,$f9:null,$f2:null,$f4:null,$f6:null,$f:null,'$m6!':function(){return this.$f7},'$m14!':function(a){this.$f7=a},'$m16!':function(a){this.$f9=a},'$m8!':function(){return this.$f9},'$m5!':function(){return this.$f6},'$m13!':function(a){this.$f6=a},'$m4!':function(){return this.$f4},'$m12!':function(a){this.$f4=a},'$m2!':function(){return this.$f2},'$m11!':function(a){this.$f2=a},'$m!':function(){return this.$f},'$m9!':function(a){this.$f=a},'$m7!':function(){return this.$f8},'$m15!':function(a){this.$f8=a},'$m1!':function(){return this.$f1},'$m10!':function(a){this.$f1=a},'$m3!':function(){return this.$f3},$f5:null,$static:{$f:0,$f1:1}}})}}})}),b.lang.module('yfiles._R',function(c){c.WMA=new b.lang.ClassDefinition(function(){return{$final:!0,$with:[a.MMA],'$m!':function(b,c){return a.KD.$f1}}})})}(y.lang.module('yfiles._R'),y));export const CenterNodesPolicy=y.radial.CenterNodesPolicy;export const RadialLayeringStrategy=y.radial.LayeringStrategy;export const RadialEdgeRoutingStrategy=y.radial.EdgeRoutingStrategy;export const RadialLayoutNodeInfo=y.radial.RadialLayoutNodeInfo;export const RadialLayout=y.radial.RadialLayout;export default y;
