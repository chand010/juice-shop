/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Component, type OnInit, inject } from '@angular/core'
import { DomSanitizer } from '@angular/platform-browser'
import { ConfigurationService } from '../Services/configuration.service'
import { FeedbackService } from '../Services/feedback.service'
import { Gallery, type GalleryRef, GalleryComponent, GalleryImageDef } from 'ng-gallery'
import { library } from '@fortawesome/fontawesome-svg-core'
import { faFacebook, faMastodon, faReddit, faSlack, faTwitter } from '@fortawesome/free-brands-svg-icons'
import { faNewspaper, faStar } from '@fortawesome/free-regular-svg-icons'
import { faStar as fasStar, faPalette, faBold } from '@fortawesome/free-solid-svg-icons'
import { catchError } from 'rxjs/operators'
import { EMPTY } from 'rxjs'
import { MatButtonModule } from '@angular/material/button'

import { TranslateModule } from '@ngx-translate/core'
import { MatCardModule } from '@angular/material/card'

library.add(faFacebook, faTwitter, faSlack, faReddit, faNewspaper, faStar, fasStar, faPalette, faMastodon, faBold)

@Component({
  selector: 'app-about',
  templateUrl: './about.component.html',
  styleUrls: ['./about.component.scss'],
  imports: [MatCardModule, TranslateModule, GalleryComponent, GalleryImageDef, MatButtonModule]
})
export class AboutComponent implements OnInit {
  private readonly configurationService = inject(ConfigurationService)
  private readonly feedbackService = inject(FeedbackService)
  private readonly sanitizer = inject(DomSanitizer)
  private readonly gallery = inject(Gallery)

  public blueSkyUrl?: string
  public mastodonUrl?: string
  public twitterUrl?: string
  public facebookUrl?: string
  public slackUrl?: string
  public redditUrl?: string
  public pressKitUrl?: string
  public nftUrl?: string
  public galleryRef: GalleryRef

  private readonly images = [
    'assets/public/images/carousel/1.jpg',
    'assets/public/images/carousel/2.jpg',
    'assets/public/images/carousel/3.jpg',
    'assets/public/images/carousel/4.jpg',
    'assets/public/images/carousel/5.png',
    'assets/public/images/carousel/6.jpg',
    'assets/public/images/carousel/7.jpg'
  ]

  private readonly stars = [
    null,
    '<i class="fas fa-star"></i><i class="far fa-star"></i><i class="far fa-star"></i><i class="far fa-star"></i><i class="far fa-star"></i>',
    '<i class="fas fa-star"></i><i class="fas fa-star"></i><i class="far fa-star"></i><i class="far fa-star"></i><i class="far fa-star"></i>',
    '<i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="far fa-star"></i><i class="far fa-star"></i>',
    '<i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="far fa-star"></i>',
    '<i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i>'
  ]

  ngOnInit (): void {
    this.galleryRef = this.gallery.ref('feedback-gallery')
    this.populateSlideshowFromFeedbacks()
    this.configurationService.getApplicationConfiguration()
      .pipe(
        catchError((err) => {
          console.error(err)
          return EMPTY
        })
 ).subscribe((config) => {
  const social = config?.application?.social;
  if (!social) return; // Guard clause: Exit early if no social config exists

  // List of fields to update
  const platforms = [
    'blueSkyUrl', 'mastodonUrl', 'twitterUrl', 'facebookUrl', 
    'slackUrl', 'redditUrl', 'pressKitUrl', 'nftUrl'
  ];

  // Update values only if they exist in the config
  platforms.forEach(key => {
    if (social[key]) {
      this[key] = social[key];
    }
  });
});
  populateSlideshowFromFeedbacks () {
    this.feedbackService
      .find()
      .pipe(
        catchError((err) => {
          console.error(err)
          return EMPTY
        })
      )
      .subscribe((feedbacks) => {
        for (let i = 0; i < feedbacks.length; i++) {

      // ✅ SAFE VERSION
this.feedbackService.find().subscribe((feedbacks) => {
  for (let i = 0; i < feedbacks.length; i++) {
    this.galleryRef.addImage({
      src: this.images[i % this.images.length],
      // Pass the data as an object, NOT as an HTML string
      args: {
        comment: feedbacks[i].comment,
        ratingDisplay: `(${this.stars[feedbacks[i].rating]})`
      }
    });
  }
});
