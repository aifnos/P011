// Execute with playwright-cli run-code --filename after the observed login,
// Text-folder navigation and first successful fixture upload. PC loopback only.
async (page) => {
  const errors=[];
  const onError=e=>errors.push(String(e));
  page.on('pageerror',onError);
  const promise=page.waitForEvent('download');
  await page.getByRole('button',{name:'下载',exact:true}).click();
  const download=await promise;
  await download.saveAs('D:/project/P011/output/playwright/p011-next-download.txt');
  if(await download.failure()) throw Error('Download failed');
  await page.setViewportSize({width:1280,height:800});
  await page.screenshot({path:'D:/project/P011/output/playwright/p011-next-transfer-desktop.png',fullPage:true});
  await page.setViewportSize({width:390,height:844});
  const fits=await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth);
  if(!fits)throw Error('Mobile page overflows horizontally');
  await page.screenshot({path:'D:/project/P011/output/playwright/p011-next-transfer-mobile.png',fullPage:true});
  await page.getByRole('button',{name:'导入到当前目录（单文件 ≤ 64 MiB）',exact:true}).setInputFiles('D:/project/P011/working/ToolboxNext-v0.5.0/tests/fixtures/upload-test.txt');
  const rejected=page.waitForResponse(r=>r.url().includes('/api/upload?')&&r.status()===409);
  await page.getByRole('button',{name:'上传所选文件',exact:true}).click();
  await rejected;
  await page.getByRole('status').filter({hasText:'同名文件已存在'}).waitFor();
  const duplicateMessage=await page.getByRole('status').textContent();
  await page.screenshot({path:'D:/project/P011/output/playwright/p011-next-transfer-duplicate.png',fullPage:true});
  page.removeListener('pageerror',onError);
  if(errors.length)throw Error(errors.join('\n'));
  return {download_event:true,download_saved:true,suggested_filename:download.suggestedFilename(),mobile_width:390,horizontal_overflow:!fits,duplicate_rejected:duplicateMessage.includes('同名文件已存在'),uncaught_page_errors:errors};
}
