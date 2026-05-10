function buildAddOn(e) {
  try {
    var accessToken = e.gmail.accessToken;
    GmailApp.setCurrentMessageAccessToken(accessToken);
    var messageId = e.gmail.messageId;
    var message = GmailApp.getMessageById(messageId);

    var subject   = message.getSubject() || "No Subject";
    var sender    = message.getFrom() || "";
    var body      = message.getPlainBody() || "";
    var userEmail = Session.getEffectiveUser().getEmail();

    var senderEmailMatch = sender.match(/<([^>]+)>/);
    var senderEmail = senderEmailMatch ? senderEmailMatch[1] : sender;
    var senderName  = sender.replace(/<[^>]+>/, "").trim();

    var links = extractLinksFromMessage(message);

    var pastSendingHours = getPastSendingHours(senderEmail);
    var currentHour      = message.getDate().getHours();
    var outboundHistory  = GmailApp.search("to:"   + senderEmail).length;
    var inboundHistory   = GmailApp.search("from:" + senderEmail).length;

    var toList     = message.getTo() ? message.getTo().split(",") : [];
    var ccList     = message.getCc() ? message.getCc().split(",") : [];
    var recipients = toList.concat(ccList)
                           .map(function(r) { return r.trim(); })
                           .filter(function(r) { return r.length > 0; });

    var payloadData = {
      "user_email":           userEmail,
      "sender_name":          senderName,
      "sender_email":         senderEmail,
      "reply_to":             message.getReplyTo() || "",
      "recipients":           recipients,
      "subject":              subject,
      "body":                 body,
      "links":                links,
      "outbound_count":       outboundHistory,
      "inbound_count":        inboundHistory,
      "current_sending_hour": currentHour,
      "past_sending_hours":   pastSendingHours
    };

    var options = {
      "method":             "post",
      "contentType":        "application/json",
      "payload":            JSON.stringify(payloadData),
      "muteHttpExceptions": true
    };

    var apiUrl   = "https://rokach-email-scorer.hf.space/analyze";
    var response = UrlFetchApp.fetch(apiUrl, options);
    var responseCode = response.getResponseCode();
    var responseText = response.getContentText();
    Logger.log("Code: " + responseCode + " Body: " + responseText);

    var jsonResponse = JSON.parse(responseText);
    if (jsonResponse.score !== undefined) {
      return buildResultCard(
        jsonResponse.score,
        jsonResponse.verdict,
        jsonResponse.reasons || [],
        jsonResponse.ai_used || false
      );
    }

    return buildResultCard(50, "SUSPICIOUS", ["This email could not be fully analyzed — treat it with caution."], false);

  } catch (e) {
    Logger.log("ERROR: " + e.toString());
    return buildResultCard(50, "SUSPICIOUS", ["This email could not be fully analyzed — treat it with caution."], false);
  }
}

function extractLinksFromMessage(message) {
  var htmlBody = message.getBody();
  var links    = [];
  var regex    = /<a\s+(?:[^>]*?\s+)?href="([^"]*)"[^>]*>(.*?)<\/a>/gi;
  var match;
  while ((match = regex.exec(htmlBody)) !== null) {
    var url  = match[1];
    var text = match[2].replace(/<\/?[^>]+(>|$)/g, "");
    if (url && text) links.push({ "text": text.trim(), "url": url.trim() });
  }
  return links;
}

function getPastSendingHours(senderEmail) {
  var threads = GmailApp.search("from:" + senderEmail, 0, 10);
  var hours   = [];
  for (var i = 0; i < threads.length; i++) {
    var date = threads[i].getMessages()[0].getDate();
    hours.push(date.getHours());
  }
  return hours;
}

function buildResultCard(score, verdict, reasons, aiUsed) {
  var color = "#4CAF50";
  if (verdict === "PHISHING")   color = "#F44336";
  if (verdict === "SUSPICIOUS") color = "#FF9800";

  var section = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText("<b>Risk Score:</b> " + score + " / 100"))
    .addWidget(CardService.newTextParagraph().setText("<b>Verdict:</b> <font color=\"" + color + "\"><b>" + verdict + "</b></font>"));

  if (aiUsed) section.addWidget(CardService.newTextParagraph().setText("🤖 Analyzed with AI"));

  if (reasons && reasons.length > 0) {
    section.addWidget(CardService.newDivider());
    section.addWidget(CardService.newTextParagraph().setText("<b>Why this was flagged:</b>"));
    for (var i = 0; i < reasons.length; i++) {
      section.addWidget(CardService.newTextParagraph().setText("⚠️  " + reasons[i]));
    }
  }

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Upwind Scorer"))
    .addSection(section)
    .build();
}